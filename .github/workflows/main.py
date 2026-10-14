"""StoxKart V14 Android client.

Kivy-based Android UI for the authenticated StoxKart API workflow. The app keeps
credentials/tokens in memory, redacts secrets from evidence, and shows raw API
responses so HTTP 200 business-level rejections aren't reported as success.
Test only with an authorized pre-production account before any live use.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import shlex
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import requests
from kivy.app import App
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView

DEFAULT_BASE_URL = "https://preprod-openapi.stoxkart.com"
DEFAULT_TOKEN_URL = "https://openapi.stoxkart.com/auth/token"
SECRET_KEYS = {"password", "secret", "api_secret", "api_key", "otp", "signature",
               "access_token", "request_token", "req_token", "authorization", "cookie"}
FAILURE_WORDS = {"error", "failed", "failure", "rejected", "reject"}


def nested_first(data, keys):
    if not isinstance(data, dict):
        return ""
    for key in keys:
        if data.get(key) not in (None, ""):
            return str(data[key])
    child = data.get("data")
    if isinstance(child, dict):
        for key in keys:
            if child.get(key) not in (None, ""):
                return str(child[key])
    return ""


def safe_url(url):
    return re.sub(r"([?&]api-key=)[^&\s]+", r"\1[REDACTED]", str(url))


def scrub(value, redact_plain_token=False):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            low = key.lower()
            if low in SECRET_KEYS or (redact_plain_token and low == "token"):
                out[key] = "[REDACTED]"
            else:
                out[key] = scrub(item, redact_plain_token)
        return out
    if isinstance(value, list):
        return [scrub(item, redact_plain_token) for item in value]
    return value


def is_business_rejection(data):
    """Detect common API-level failures even when HTTP status is 200.
    This is intentionally conservative; raw response is always shown to the user.
    """
    if not isinstance(data, dict):
        return False
    for obj in (data, data.get("data") if isinstance(data.get("data"), dict) else {}):
        if obj.get("success") is False or obj.get("ok") is False:
            return True
        for key in ("error", "errors"):
            value = obj.get(key)
            if value not in (None, "", [], {}):
                return True
        status = str(obj.get("status", "")).strip().lower()
        if status in FAILURE_WORDS:
            return True
    return False


class StoxKartAndroid(App):
    def build(self):
        self.title = "StoxKart V14"
        self.session = requests.Session()
        self.access_token = ""
        self.login_token = ""
        self.request_token = ""
        self.last_order_id = ""
        self.events = []
        self.busy = False
        self.lock = threading.Lock()

        outer = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(8))
        header = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(58), spacing=dp(2))
        header.add_widget(Label(text="StoxKart V14 Mock Audit Runner", bold=True, font_size="20sp", size_hint_y=None, height=dp(32)))
        header.add_widget(Label(text="Review the selected API host before submitting an order", font_size="11sp", size_hint_y=None, height=dp(20), color=(1, .65, .35, 1)))
        outer.add_widget(header)

        scroll = ScrollView(do_scroll_x=False)
        self.form = BoxLayout(orientation="vertical", padding=dp(4), spacing=dp(6), size_hint_y=None)
        self.form.bind(minimum_height=self.form.setter("height"))
        scroll.add_widget(self.form)
        outer.add_widget(scroll)

        self.fields = {}
        self.add_section("1. API authentication")
        for key, label, default, secret in [
            ("base_url", "API base URL", DEFAULT_BASE_URL, False),
            ("token_url", "Access-token URL", DEFAULT_TOKEN_URL, False),
            ("client_id", "Client ID / user ID", "", False),
            ("password", "Password", "", True),
            ("api_key", "API key", "", True),
            ("secret", "Secret key", "", True),
            ("totp", "Current 6-digit TOTP", "", True),
            ("algo_id", "X-Algo-Id", "99999", False),
            ("amo_place_cookie", "AMO place Cookie (optional)", "", True),
            ("amo_modify_cookie", "AMO modify Cookie (optional)", "", True),
            ("amo_cancel_cookie", "AMO cancel Cookie (optional)", "", True),
        ]:
            self.add_text_field(key, label, default, secret)
        self.add_button("GENERATE ACCESS TOKEN", self.authenticate, primary=True)
        self.auth_status = self.add_label("Authentication: NOT AUTHENTICATED", color=(1, .35, .35, 1))

        self.add_section("2. Order request")
        self.mode = self.add_spinner("Trade mode", ["NORMAL", "AMO"], "NORMAL", self._mode_changed)
        self.exchange_key_label = self.add_label("Payload exchange key: exchange_segment")
        for key, label, default, secret in [
            ("exchange", "Exchange value (e.g. NSE / NFO)", "NSE", False),
            ("token", "Instrument token", "", False),
            ("quantity", "Quantity", "1", False),
            ("price", "Price (0 for market where supported)", "0", False),
            ("order_id", "Order ID (modify/cancel)", "", False),
        ]:
            self.add_text_field(key, label, default, secret)
        self.action = self.add_spinner("Action", ["BUY", "SELL"], "BUY")
        self.order_type = self.add_spinner("Order type", ["MARKET", "LIMIT", "SL", "SL-M"], "MARKET")
        self.product_type = self.add_spinner("Product type", ["DELIVERY", "INTRADAY", "CARRYFORWARD"], "INTRADAY")
        self.quantity_type = self.add_spinner("Quantity type", ["LOTS", "QUANTITY"], "QUANTITY")
        self.validity = self.add_spinner("Validity", ["DAY", "IOC"], "DAY")
        grid = GridLayout(cols=2, spacing=dp(5), size_hint_y=None, height=dp(142))
        for text, fn in [("PLACE ORDER", self.place_order), ("MODIFY ORDER", self.modify_order),
                         ("CANCEL ORDER", self.cancel_order), ("ORDER BOOK", lambda: self.api("Order Book", "GET", "/reports/v3/order-book")),
                         ("FUNDS", lambda: self.api("Funds", "GET", "/funds")),
                         ("HOLDINGS", lambda: self.api("Holdings", "GET", "/portfolio/holdings"))]:
            b = Button(text=text, size_hint_y=None, height=dp(44))
            b.bind(on_release=lambda _b, action=fn: self.run_async(action))
            grid.add_widget(b)
        self.form.add_widget(grid)

        self.add_section("3. Account, portfolio & reporting")
        grid2 = GridLayout(cols=2, spacing=dp(5), size_hint_y=None, height=dp(188))
        api_actions = [
            ("POSITIONS", lambda: self.api("Positions", "GET", "/portfolio/v3/positions")),
            ("TRADE BOOK", lambda: self.api("Trade Book", "GET", "/reports/trade-book")),
            ("MARGIN CHECK", self.margin),
            ("USER DETAILS", lambda: self.api("User Details", "GET", "/reports/user-details")),
            ("SCRIPT MASTER", self.script_master),
            ("CONVERT POSITION", self.convert_position),
            ("EXPORT JSON + HTML AUDIT", self.export_report),
        ]
        for text, fn in api_actions:
            b = Button(text=text, size_hint_y=None, height=dp(44), font_size="12sp")
            b.bind(on_release=lambda _b, action=fn: self.run_async(action))
            grid2.add_widget(b)
        self.form.add_widget(grid2)
        self.new_product_type = self.add_spinner("Convert to product type", ["DELIVERY", "INTRADAY", "CARRYFORWARD"], "DELIVERY")

        self.add_section("4. API response / audit log")
        self.log_view = TextInput(text="Ready. No API request has been sent.", readonly=True, multiline=True,
                                  size_hint_y=None, height=dp(290), font_size="12sp")
        self.form.add_widget(self.log_view)
        self.add_button("CLEAR LOG", self.clear_log)
        return outer

    def add_section(self, text):
        self.form.add_widget(Label(text=text, bold=True, font_size="16sp", halign="left", valign="middle", size_hint_y=None, height=dp(30)))

    def add_label(self, text, color=(.9, .9, .9, 1)):
        lab = Label(text=text, color=color, halign="left", valign="middle", size_hint_y=None, height=dp(28))
        lab.bind(size=lambda w, *_: setattr(w, "text_size", (w.width, None)))
        self.form.add_widget(lab)
        return lab

    def add_text_field(self, key, label, default="", secret=False):
        self.add_label(label)
        inp = TextInput(text=default, hint_text=label, password=secret, multiline=False,
                        size_hint_y=None, height=dp(44), padding=(dp(9), dp(10)))
        self.fields[key] = inp
        self.form.add_widget(inp)
        return inp

    def add_spinner(self, label, values, default, on_change=None):
        self.add_label(label)
        w = Spinner(text=default, values=tuple(values), size_hint_y=None, height=dp(44))
        if on_change:
            w.bind(text=on_change)
        self.form.add_widget(w)
        return w

    def add_button(self, text, fn, primary=False):
        b = Button(text=text, size_hint_y=None, height=dp(48))
        if primary:
            b.background_color = (.12, .45, .8, 1)
        b.bind(on_release=lambda _b: self.run_async(fn))
        self.form.add_widget(b)
        return b

    def _mode_changed(self, _spinner, value):
        self.exchange_key_label.text = "Payload exchange key: " + ("exchange_segment" if value == "NORMAL" else "exchange")

    def val(self, key):
        return self.fields[key].text.strip()

    def log(self, text):
        Clock.schedule_once(lambda _dt: self._append_log(text))

    def _append_log(self, text):
        if not hasattr(self, "log_view"):
            return
        self.log_view.text = (self.log_view.text + "\n" + str(text))[-24000:]
        self.log_view.cursor = (0, len(self.log_view.text.splitlines()))

    def clear_log(self):
        self.log_view.text = ""

    def run_async(self, fn):
        if self.busy:
            self.log("Please wait for the current request to finish.")
            return
        self.busy = True
        self.log("Working…")
        def worker():
            try:
                with self.lock:
                    fn()
            except Exception as exc:
                self.log("ERROR: " + str(exc))
            finally:
                self.busy = False
        threading.Thread(target=worker, daemon=True).start()

    def validate_url(self, url, label):
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.netloc:
            raise ValueError(f"{label} must be a complete http:// or https:// URL.")

    def call(self, name, method, url, headers, body=None, auth_sensitive=False):
        self.validate_url(url, "API URL")
        stamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
        start = time.monotonic()
        resp = self.session.request(method, url, headers=headers, json=body, timeout=30)
        elapsed = round((time.monotonic() - start) * 1000, 2)
        try:
            data = resp.json()
        except ValueError:
            data = {"raw": resp.text[:6000]}
        ok = resp.ok and not is_business_rejection(data)
        red_headers = {k: ("[REDACTED]" if k.lower() in {"x-access-token", "x-api-key", "authorization", "cookie"} else v)
                       for k, v in headers.items()}
        request_body = scrub(body or {}, redact_plain_token=auth_sensitive)
        response_body = scrub(data, redact_plain_token=auth_sensitive)
        url_clean = safe_url(url)
        curl_parts = ["curl", "--request", method, "--url", shlex.quote(url_clean)]
        for k, v in red_headers.items():
            curl_parts += ["--header", shlex.quote(f"{k}: {v}")]
        if body is not None:
            curl_parts += ["--data", shlex.quote(json.dumps(request_body, ensure_ascii=False))]
        ev = {"name": name, "method": method, "url": url_clean, "status": "PASS" if ok else "FAIL",
              "status_code": resp.status_code, "timestamp": stamp, "duration_ms": elapsed,
              "request_headers": red_headers, "request_body": request_body,
              "response_body": response_body, "curl": " ".join(curl_parts), "trade_mode": self.mode.text}
        self.events.append(ev)
        self.log(f"\n{name} — HTTP {resp.status_code} — {'PASS' if ok else 'FAIL'} ({elapsed} ms)\n"
                 f"Response:\n{json.dumps(response_body, indent=2, ensure_ascii=False)[:7000]}\n\n"
                 f"Generated cURL (sensitive values redacted):\n{ev['curl']}")
        return resp, data, ok

    def authenticate(self):
        base = (self.val("base_url") or DEFAULT_BASE_URL).rstrip("/")
        token_url = self.val("token_url") or DEFAULT_TOKEN_URL
        api_key, secret = self.val("api_key"), self.val("secret")
        client_id, password, otp = self.val("client_id"), self.val("password"), self.val("totp")
        if not all((api_key, secret, client_id, password, otp)):
            raise ValueError("Fill Client ID, password, API key, secret key, and current TOTP first.")
        if not re.fullmatch(r"\d{6}", otp):
            raise ValueError("TOTP must be exactly six digits.")
        r, data, ok = self.call("Login", "POST", f"{base}/auth/login?api-key={api_key}",
                                {"Content-Type": "application/json"},
                                {"platform": "api", "data": {"client_id": client_id, "password": password}}, True)
        login_token = nested_first(data, ["token"])
        if not ok or not login_token:
            self._set_auth_status(False)
            raise RuntimeError("Login failed. Review the API response and verify test credentials.")
        r, data, ok = self.call("2FA API Key", "POST", f"{base}/auth/twofa/verify?api-key={api_key}",
                                {"Content-Type": "application/json"},
                                {"platform": "api", "data": {"client_id": client_id, "token": login_token,
                                                                    "action": "api-key-validation", "otp": otp}}, True)
        request_token = nested_first(data, ["request_token", "req_token"])
        if not ok or not request_token:
            self._set_auth_status(False)
            raise RuntimeError("2FA failed. Review the API response and verify the current TOTP.")
        signature = hmac.new((api_key + request_token).encode(), secret.encode(), hashlib.sha256).hexdigest()
        r, data, ok = self.call("Get access token", "POST", token_url, {"Content-Type": "application/json"},
                                {"api_key": api_key, "signature": signature, "req_token": request_token}, True)
        access = nested_first(data, ["access_token", "token"])
        if not ok or not access:
            self._set_auth_status(False)
            raise RuntimeError("Access-token request failed. Review the API response.")
        self.login_token = login_token
        self.request_token = request_token
        self.access_token = access
        self.log("AUTHENTICATION SUCCESS. Access token remains in memory for this app session only.")
        self._set_auth_status(True)

    def _set_auth_status(self, success):
        Clock.schedule_once(lambda _dt: self._apply_auth_status(success))

    def _apply_auth_status(self, success):
        self.auth_status.text = "Authentication: AUTHENTICATED" if success else "Authentication: NOT AUTHENTICATED"
        self.auth_status.color = (0.25, 0.9, 0.45, 1) if success else (1, 0.35, 0.35, 1)

    def headers(self, operation="place"):
        if not self.access_token:
            raise RuntimeError("Generate the access token first.")
        headers = {"X-Client-Id": self.val("client_id"), "X-Access-Token": self.access_token,
                   "X-Platform": "api", "X-Api-Key": self.val("api_key"), "Content-Type": "application/json"}
        algo = self.val("algo_id") or "99999"
        if self.mode.text == "NORMAL":
            headers.update({"X-Algo-Id": algo, "X-Algo_Id": algo, "X-Version": "v3.0.0"})
        elif operation == "place":
            headers["X-Algo-Id"] = algo
        cookie_key = {"place": "amo_place_cookie", "modify": "amo_modify_cookie", "cancel": "amo_cancel_cookie"}.get(operation)
        cookie = self.val(cookie_key) if cookie_key else ""
        if self.mode.text == "AMO" and cookie:
            headers["Cookie"] = cookie
        return headers

    def order_values(self):
        exchange = self.val("exchange")
        token = self.val("token")
        quantity = self.val("quantity")
        price = self.val("price") or "0"
        if not exchange or not token or not quantity:
            raise ValueError("Exchange value, instrument token, and quantity are required.")
        if not quantity.isdigit() or int(quantity) <= 0:
            raise ValueError("Quantity must be a positive whole number.")
        return {"exchange": exchange, "token": token, "action": self.action.text,
                "order_type": self.order_type.text, "product_type": self.product_type.text,
                "quantity_type": self.quantity_type.text, "quantity": quantity, "price": price,
                "validity": self.validity.text}

    def place_order(self):
        p = self.order_values()
        mode = self.mode.text
        base = (self.val("base_url") or DEFAULT_BASE_URL).rstrip("/")
        body = {"variety": "NORMAL", "action": p["action"], "token": p["token"],
                "order_type": p["order_type"], "product_type": p["product_type"],
                "quantity_type": p["quantity_type"], "quantity": p["quantity"],
                "disclose_quantity": "0", "price": p["price"], "trigger_price": "0",
                "stop_loss_price": "0", "trailing_stop_loss": "0", "validity": p["validity"], "tag": ""}
        if mode == "NORMAL":
            body["exchange_segment"] = p["exchange"]
            path = "/orders/v3/place"
        else:
            body["exchange"] = p["exchange"]
            path = "/orders/amo"
        r, data, ok = self.call(mode + " - Place Order", "POST", base + path, self.headers("place"), body)
        oid = nested_first(data, ["order_id", "orderId", "id"])
        if oid:
            self.last_order_id = oid
            Clock.schedule_once(lambda _dt: setattr(self.fields["order_id"], "text", oid))
        if not ok:
            raise RuntimeError("Order placement was rejected or failed. Read the broker response in the log; do not assume it was placed.")
        if not oid:
            self.log("The API returned HTTP success but no order ID was found. Verify the response/order book before retrying to avoid a duplicate order.")

    def modify_order(self):
        p = self.order_values()
        oid = self.val("order_id") or self.last_order_id
        if not oid:
            raise ValueError("Enter the broker order ID before modifying.")
        mode = self.mode.text
        base = (self.val("base_url") or DEFAULT_BASE_URL).rstrip("/")
        if mode == "NORMAL":
            body = {"variety": "NORMAL", "order_id": oid, "exchange_segment": p["exchange"], "token": p["token"],
                    "order_type": p["order_type"], "quantity_type": p["quantity_type"], "quantity": p["quantity"],
                    "disclose_quantity": "0", "price": p["price"], "stop_loss_price": "0",
                    "trigger_price": "0", "validity": p["validity"]}
            method, url = "POST", base + "/orders/v3/modify"
        else:
            body = {"exchange": p["exchange"], "token": p["token"], "order_type": p["order_type"],
                    "quantity": p["quantity"], "disclose_quantity": "0", "price": p["price"],
                    "stop_loss_price": "0", "trigger_price": "0", "validity": ""}
            method, url = "PUT", base + "/orders/amo/" + oid
        _r, _data, ok = self.call(mode + " - Modify Order", method, url, self.headers("modify"), body)
        if not ok:
            raise RuntimeError("Modify was rejected or failed. Read the broker response in the log.")

    def cancel_order(self):
        oid = self.val("order_id") or self.last_order_id
        if not oid:
            raise ValueError("Enter the broker order ID before cancelling.")
        mode = self.mode.text
        base = (self.val("base_url") or DEFAULT_BASE_URL).rstrip("/")
        if mode == "NORMAL":
            method, url, body = "POST", base + "/orders/v3/cancel", {"variety": "NORMAL", "order_id": oid}
        else:
            method, url, body = "DELETE", base + "/orders/amo/" + oid, None
        _r, _data, ok = self.call(mode + " - Cancel Order", method, url, self.headers("cancel"), body)
        if not ok:
            raise RuntimeError("Cancel was rejected or failed. Read the broker response in the log.")

    def api(self, name, method, path, body=None, algo_header=False):
        base = (self.val("base_url") or DEFAULT_BASE_URL).rstrip("/")
        headers = self.headers("other")
        if algo_header:
            headers["X-Algo_Id"] = self.val("algo_id") or "99999"
        _r, _data, ok = self.call(name, method, base + path, headers, body)
        if not ok:
            raise RuntimeError(f"{name} failed. Read the broker response in the log.")

    def margin(self):
        p = self.order_values()
        body = {"action": p["action"], "exchange_segment": p["exchange"], "token": p["token"],
                "order_type": p["order_type"], "product_type": p["product_type"], "quantity_type": p["quantity_type"],
                "quantity": p["quantity"], "price": p["price"] if p["order_type"] == "LIMIT" else "0", "trigger_price": "0"}
        self.api("Margin", "POST", "/orders/v3/margin", body, algo_header=True)

    def convert_position(self):
        p = self.order_values()
        body = {"exchange_segment": p["exchange"], "token": p["token"], "quantity_type": p["quantity_type"],
                "quantity": p["quantity"], "action": p["action"], "product_type": p["product_type"],
                "new_product_type": self.new_product_type.text}
        self.api("Position Conversion", "PUT", "/portfolio/v3/position-conversion", body)

    def script_master(self):
        self.api("Script Master", "POST", "/reports/script-master", {"exch": self.val("exchange")})

    def export_report(self):
        out = Path(self.user_data_dir)
        out.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S")
        json_path = out / f"StoxKart_V14_Audit_{stamp}.json"
        html_path = out / f"StoxKart_V14_Audit_{stamp}.html"
        evidence = {"generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                    "trade_mode": self.mode.text, "api_base_url": safe_url(self.val("base_url") or DEFAULT_BASE_URL),
                    "event_count": len(self.events), "events": self.events}
        json_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
        rows = []
        for ev in self.events:
            rows.append("<section><h2>" + str(ev.get("name", "API call")) + "</h2><p>" + str(ev.get("status")) +
                        " | HTTP " + str(ev.get("status_code")) + " | " + str(ev.get("timestamp")) +
                        "</p><h3>Request</h3><pre>" + _html(json.dumps(ev.get("request_body"), indent=2, ensure_ascii=False)) +
                        "</pre><h3>Response</h3><pre>" + _html(json.dumps(ev.get("response_body"), indent=2, ensure_ascii=False)) +
                        "</pre><h3>cURL (redacted)</h3><pre>" + _html(ev.get("curl", "")) + "</pre></section>")
        html_doc = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>StoxKart V14 Audit</title><style>body{font:16px sans-serif;max-width:950px;margin:20px auto;padding:0 12px;background:#f5f7fa;color:#152238}section{background:white;border:1px solid #ccd4df;border-radius:8px;padding:14px;margin:14px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f8;padding:10px}</style></head><body><h1>StoxKart V14 Mock Audit Evidence</h1><p>Generated: " + _html(evidence["generated_at"]) + "</p><p>Trade mode: " + _html(evidence["trade_mode"]) + "</p>" + "".join(rows) + "</body></html>"
        html_path.write_text(html_doc, encoding="utf-8")
        self.log(f"\nAudit evidence exported to app-private storage:\n{json_path}\n{html_path}\nEvents recorded: {len(self.events)}\nSensitive API credentials are redacted.")


def _html(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


if __name__ == "__main__":
    StoxKartAndroid().run()

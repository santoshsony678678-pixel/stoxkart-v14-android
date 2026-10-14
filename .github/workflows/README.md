# StoxKart V14 Android source package

Upload this ZIP to the root of the GitHub repository as `StoxKart_V14_Android_Real_Project.zip`.

The GitHub Actions workflow is created separately at `.github/workflows/build-apk.yml`. It extracts this ZIP, checks `main.py` and `buildozer.spec`, checks Python syntax, builds a debug APK with Buildozer, and uploads an APK artifact if the build succeeds.

This is a Kivy Android rewrite, not the original Tkinter desktop UI. Live StoxKart API and order placement have not been verified. Use only authorized pre-production test credentials until API behavior is validated.

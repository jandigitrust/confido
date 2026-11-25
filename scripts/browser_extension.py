"""Launch an installed Chromium extension for browser acceptance checks."""


def installed_page(playwright, extension, profile, *, headless=True):
    """Return the context and verifier page; close the context if startup fails.

    The caller owns a successfully opened context and must close it after use.
    """
    context = playwright.chromium.launch_persistent_context(
        profile,
        channel="chromium",
        headless=headless,
        args=[
            f"--disable-extensions-except={extension}",
            f"--load-extension={extension}",
        ],
    )
    try:
        worker = (
            context.service_workers[0]
            if context.service_workers
            else context.wait_for_event("serviceworker")
        )
        page = context.new_page()
        page.goto("chrome-extension://" + worker.url.split("/")[2] + "/index.html")
        return context, page
    except Exception:
        context.close()
        raise

# Run Avishkar on your PC

You need **Python 3.10 or newer**. Check with `python --version`.

1. Unzip this folder and open a terminal inside it (the folder that contains `requirements.txt`).
2. Install the dependencies (first time only):

   ```
   python -m pip install -r requirements.txt
   ```

3. Start the site:

   ```
   python -m avishkar serve --port 8011 --db data/local.db
   ```

4. Open **http://127.0.0.1:8011** in your browser.

## Signing in to the dashboard

On the very first start, the terminal prints a line like:

```
First-run admin created: admin@avishkar.local / <password>
```

Sign in with that email and the password after the ` / `. There is no self sign-up.
The password is printed only once, so copy it then. If you lose it, create your own admin instead:

```
python -m avishkar create-user --email you@example.com --role admin --db data/local.db
```

(it asks you to type a password; nothing shows while you type, that's normal)

## Notes

- The page works offline: fonts, Three.js and GSAP are bundled in `web/vendor/`.
- Sessions reset whenever the server restarts, so you'll need to sign in again after a restart.
- To scan something quickly, zip `sample_projects/vulnerable-python` and upload it from the dashboard.
- Run the tests with `python -m pytest tests/unit tests/integration -q`.

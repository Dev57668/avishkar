import os
from flask import Flask

app = Flask(__name__)
app.config["DEBUG"] = True


if __name__ == "__main__":
    app.run(debug=os.getenv("APP_DEBUG") == "1")

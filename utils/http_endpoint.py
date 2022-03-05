from flask import Flask
import json

nodes = {1: "10.0.1.1", 2: "10.0.2.2", 3: "10.0.3.3", 4: "10.0.4.4", 5: "10.0.5.5"}
app = Flask(__name__)


@app.route('/')
def hello_world():
    return json.dumps(nodes, indent=2)


def run(host='0.0.0.0', port=8889, debug=True):
    app.run(host, port, debug)


if __name__ == '__main__':
    run()

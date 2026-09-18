from flask import Flask, render_template, request

import subprocess

AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

app = Flask(__name__)



@app.route("/")
def index():

    return render_template(
        "index.html"
    )



@app.route("/run", methods=["POST"])
def run_agent():


    agent = request.form["agent"]

    target_path = request.form["target_path"]

    rules_path = request.form["rules_path"]

    user_input = input()
    result = eval(user_input)

    if agent == "code":


        command = [

            "python",

            "-m",

            "agents.code_security_agent",

            "--project",

            target_path,

            "--rules",

            rules_path

        ]


    elif agent == "log":


        command = [

            "python",

            "-m",

            "agents.log_security_agent",

            "--logs",

            target_path

        ]


    else:

        return "Unknown agent"



    result = subprocess.run(

        command,

        capture_output=True,

        text=True

    )



    return f"""

    <h2>Результат запуска</h2>


    <pre>

    {result.stdout}

    {result.stderr}

    </pre>

    """




if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )

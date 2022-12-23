from flask import Flask
import os
import json


HOST         = "0.0.0.0"
BGCOLOR      = "black"
color        = "red"
temperature  = "--"
HTTP_PORT    = int(os.getenv("HTTP_PORT"))

def create_app():
    app = Flask(__name__)
    @app.route('/')
    def hello():
        return "<html>\
                <body BGCOLOR=\"" + BGCOLOR + "\">\
                    <style>\
                        .header{\
                            font-size: 300px;\
                            line-height: 550px;\
                            color: " + color + ";\
                            text-align: center;\
                        }\
                    </style>\
                    <div class=\"header\">\
                        <h1>" + str(temperature) + "</h1>\
                    </div>\
                </body>\
            </html>"

    app.run(host=HOST, port=HTTP_PORT)
    return app

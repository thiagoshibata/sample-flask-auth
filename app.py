from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager

app = Flask(__name__)
# configurar uma chave secreta
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# construir view login

# session -> conexão ativa

@app.route('/login', methods=['POST'])
def login():
  data = request.json
  username = data.get("username")
  password = data.get("password")

  if username and password:
    # Login - procurar o usuário 
    pass
  return jsonify({"message":"Credenciais inválidas"}), 400

@app.route("/hello-world", methods=['GET'])
def hello_world():
  return "Hellor world"

if __name__ == '__main__':
  app.run(debug=True)
from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user,login_required

app = Flask(__name__)
# configurar uma chave secreta
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# construir view login (rota de login)
login_manager.login_view = 'login'

# recuperando o registro do usuário no banco de dados.
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
  data = request.json
  username = data.get("username")
  password = data.get("password")

  if username and password:
    # Login - procurando usuário no banco de dados
    user = User.query.filter_by(username=username).first()

    if user and user.password == password:
      login_user(user)
      print(current_user.is_authenticated)
      return jsonify({"message":"Autenticação realizada com sucesso!"}),200
    else:
      return jsonify({"message":"Usuário ou senha inválidos"})
  return jsonify({"message":"Credenciais inválidas"}), 400

@app.route('/logout', methods=['GET'])
@login_required # Somente usuários autenticados. || Protegida
def logout():
  
  logout_user()
  return jsonify({"message":"Logout realizado com sucesso"})

@app.route('/user', methods=['POST'])
def create_user():
  data = request.json
  username = data.get('username')
  password = data.get('password')

  if username and password:
    user_exists = User.query.filter_by(username=username).first()
    if not user_exists:
      user = User(username=username, password=password)
      db.session.add(user)
      db.session.commit()
      return jsonify({"message":"Usuário cadastrado com sucesso"})
    
    return jsonify({"message":"Usuário já cadastrado! Informe um novo usuário"})
    
  return jsonify({"message":"Dados inválidos"}),400

@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
  user = User.query.get(id_user)
  if user:
    return {"username":user.username}
  return jsonify({"message":"Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
  data = request.json
  user = User.query.get(id_user)

  if user and data.get('password'):
    user.password = data.get('password')
    db.session.commit()

    return jsonify({"message": f"Usuário {id_user} atualizado com sucesso"})
    
  return jsonify({"message":"Usuário não encontrado"}), 404

if __name__ == '__main__':
  app.run(debug=True)
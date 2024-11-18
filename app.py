from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user,login_required
import bcrypt

app = Flask(__name__)
# configurar uma chave secreta
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# construir view login (rota de login)
login_manager.login_view = 'login'

# recuperando o registro do usuário no banco de dados.
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(user_id)

# LOGIN
@app.route('/login', methods=['POST'])
def login():
  data = request.json
  username = data.get("username")
  password = data.get("password")

  if username and password:
    # Login - procurando usuário no banco de dados
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
      login_user(user)
      return jsonify({"message":"Autenticação realizada com sucesso!"}),200
    else:
      return jsonify({"message":"Usuário ou senha inválidos"})
  return jsonify({"message":"Credenciais inválidas"}), 400

# LOGOUT 
@app.route('/logout', methods=['GET'])
@login_required # Somente usuários autenticados. || Protegida
def logout():
  
  logout_user()
  return jsonify({"message":"Logout realizado com sucesso"})

# CREATE
@app.route('/user', methods=['POST'])
def create_user():
  data = request.json
  username = data.get('username')
  password = data.get('password')

  if username and password:
    user_exists = User.query.filter_by(username=username).first()
    if not user_exists:
      hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
      user = User(username=username, password=hashed_password, role='user')
      db.session.add(user)
      db.session.commit()
      return jsonify({"message":"Usuário cadastrado com sucesso"})
    
    return jsonify({"message":"Usuário já cadastrado! Informe um novo usuário"})
    
  return jsonify({"message":"Dados inválidos"}),400

# READ 
@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
  user = User.query.get(id_user)
  if user:
    return {"username":user.username}
  return jsonify({"message":"Usuário não encontrado"}), 404

# UPDATE
@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
  data = request.json
  user = User.query.get(id_user)

  if id_user != current_user.id and current_user.role == "user":
    return jsonify({"message":"Operação não autorizada."}), 403

  if user and data.get('password'):
    user.password = data.get('password')
    db.session.commit()

    return jsonify({"message": f"Usuário: {id_user} atualizado com sucesso"})
    
  return jsonify({"message":"Usuário não encontrado"}), 404

# DELETE
@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
  user = User.query.get(id_user)

  if current_user.role != 'admin':
    return jsonify({"message":"Operação não autorizada"}), 403

  # Não permite que o sistema exclua o usuário que está logado.
  if id_user == current_user.id:
    return jsonify({"message":"Não é permitido excluir este usuário. Faça o login com outra conta para excluí-lo."}), 403
  
  if user:
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message":f"Usuário:{id_user} deletado com sucesso"})
  
  return jsonify({"message":f"Usuário não encontrado"}), 404
  
  

if __name__ == '__main__':
  app.run(debug=True)
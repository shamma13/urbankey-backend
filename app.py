#import dependencies
from flask import Flask, jsonify, request
from flask_cors import CORS
import jwt
from functools import wraps
from flask_bcrypt import Bcrypt
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

#import functionality classes
from UserClass import UserC
from Token import Token

#create flask project
app = Flask(__name__)

#set up the CORS
CORS(app, origins='http://localhost:3000', methods=['GET', 'POST', 'OPTIONS'])

#setting up the bcrypt
bcrypt = Bcrypt(app)

#setting up the database
uri = "mongodb+srv://admin:urbankey1234@urbankey.nfdot4b.mongodb.net/?retryWrites=true&w=majority&appName=UrbanKey"
client = MongoClient(uri, server_api=ServerApi('1'))

db = client.get_database('UrbanKey')
users = db.get_collection('Users')


# secret Key 
app.config['SECRET_KEY'] = '0622d0d552f33f6309180901'

#creating our functional objects
tokenObject = Token()
userObject = UserC(users, bcrypt)

#@wraps decorater for required token implementation here
#this wrapper will validate the token and return exceptions if needed
#exceptions handled are { token expired, token algo wrong, token invalid, decoding error, general expection as e for unexpecfed error}
#if problem with token, will send back tokenValidResponse : 1
#if problem is good, the routes will send back tokenValidResponse : 0 always as a good entry
def token_required_user(f):
    @wraps(f)
    #this is for the user
    def decorator(*args, **kwargs):

        #the token should be in the headers
        token = request.headers['token']
        
        if not token:
            return jsonify({'tokenValidResponse': '1', 'message' : 'token not provided with request'}), 401
        
        try:
            #try decoding the token
            givenToken = jwt.decode(token, app.config['SECRET_KEY'] , algorithms=['HS256'] )
            
            #get the payload which contains the info
            payload = givenToken[payload]

            #get the email from the user
            email = payload['user']
            
            print(f'Email from token inside token_required_user @wraps: {email}')

            #do this function to check if the user exists in the database
            userCheck = userObject.userExistence(email)

            #if the user exist the method above should return 1
            if userCheck == 1:
                print("token validated in @wraps token_required")
                return f(*args, **kwargs)
            
            #if we didnt find the user inside database // basically wrong token payload but correct token
            elif userCheck == 2:
                return jsonify({'tokenValidResponse' : '1',
                            'message': 'Didnt find user inside database'}), 401
            
            #basically the return value 3 or anything else in method userexistence of userClass
            else:
                return jsonify({'tokenValidResponse' : '1',
                            'message': 'Problem with userExistence // userClass'}), 401

        except jwt.ExpiredSignatureError as e:
            print("exception thrown inside wraps")
            print("token expired")
            return jsonify({'tokenValidResponse' : '1',
                            'message': 'Token has expired'}), 401
        
        except jwt.InvalidAlgorithmError as e:
            print("exception thrown inside wraps")
            print("algorithm is invalid")
            return jsonify({'tokenValidResponse': '1',
                            'message': 'token is has invalid algorithm'}), 401
        
        except jwt.InvalidTokenError as e:
            print("exception thrown inside wraps")
            print("token structure is invalid")
            return jsonify({'tokenValidResponse': '1',
                            'message': 'token structure is wrong'}), 401
        
        
        except Exception as e:
            print('enexpected error occured inside @wraps')
            return jsonify({'tokenValidResponse': '1',
                            'message': 'unexpected error inside @wraps'}), 401
    
    return decorator

def token_required_employee(f):
    @wraps(f)
    #this is for the user
    def decorator(*args, **kwargs):

        #the token should be in the headers
        token = request.headers['token']
        
        if not token:
            return jsonify({'tokenValidResponse': '1', 'message' : 'token not provided with request'}), 401
        
        try:
            #try decoding the token
            givenToken = jwt.decode(token, app.config['SECRET_KEY'] , algorithms=['HS256'] )
            
            #get the payload which contains the info
            payload = givenToken[payload]

            #get the email from the user
            email = payload['user']
            
            print(f'Email from token inside token_required_user @wraps: {email}')

            #do this function to check if the user exists in the database
            userExistenceCheck = userObject.userExistence(email)

            #if the user exist the method above should return 1
            if userExistenceCheck == 1:

                #more code for the employee functionality

                #get the user type from payload of token
                userType = payload['type']

                #get the user type based from database with method checkTypeMatch from userClass
                userTypeCheck = userObject.checkTypeMatch(email, userType, 'employee')

                #if returned 1, then good match, user type is employee
                if userTypeCheck == 1:

                    print("token validated for employee in @wraps token_required")
                    return f(*args, **kwargs)
                
                #returns 2 if not matched with employee
                elif userTypeCheck == 2: 
                    return jsonify({'tokenValidResponse' : '1',
                            'message': 'Not an employee'}), 401
                
                #returrn 3 if token type and doc type dont match
                elif userTypeCheck == 3:
                    return jsonify({'tokenValidResponse' : '1',
                            'message': 'doc type and token type not match'}), 401
                
                #return 4 if user not found
                elif userTypeCheck == 4:
                    return jsonify({'tokenValidResponse' : '1',
                            'message': 'user not found inside db'}), 401
                
                #for return 5 which is an error inside checkMatchtype in userClass
                else: 
                    return jsonify({'tokenValidResponse' : '1',
                            'message': 'Internal error inside userClass/checkTypeMatch'}), 401
            
            #if we didnt find the user inside database // basically wrong token payload but correct token
            elif userExistenceCheck == 2:
                return jsonify({'tokenValidResponse' : '1',
                            'message': 'Didnt find user inside database'}), 401
            
            #basically the return value 3 or anything else in method userexistence of userClass
            else:
                return jsonify({'tokenValidResponse' : '1',
                            'message': 'Problem with userExistence // userClass'}), 401

        except jwt.ExpiredSignatureError as e:
            print("exception thrown inside wraps")
            print("token expired")
            return jsonify({'tokenValidResponse' : '1',
                            'message': 'Token has expired'}), 401
        
        except jwt.InvalidAlgorithmError as e:
            print("exception thrown inside wraps")
            print("algorithm is invalid")
            return jsonify({'tokenValidResponse': '1',
                            'message': 'token is has invalid algorithm'}), 401
        
        except jwt.InvalidTokenError as e:
            print("exception thrown inside wraps")
            print("token structure is invalid")
            return jsonify({'tokenValidResponse': '1',
                            'message': 'token structure is wrong'}), 401
        
        
        except Exception as e:
            print('enexpected error occured inside @wraps')
            return jsonify({'tokenValidResponse': '1',
                            'message': 'unexpected error inside @wraps'}), 401
    
    return decorator

@app.route('/')
def index():
    return 'Welcome to the homepage!'

@app.route("/Login", methods=['POST'])
def login():
    #things to do
        #finish up the login
        #send type
    try:
        data = request.get_json()
        print(data);
        email = data['email']
        password = data['password']
        print(email)
        print(password)
        
        checkValue = userObject.validateUser(email, password)
        print(checkValue)
        print('checkValue above')
        if(checkValue == 1):
            
            newToken = tokenObject.create_token(email)

            newType = userObject.getType(email)

            if (newType == 1):
                print("inside newtype == 1")
                return jsonify({
                'wrong':'wrong'
            }), 403

            elif (newType == 2):
                print("newType == 2")
                return jsonify({
                'wrong':'wrong'
            }), 403

            elif (newType == 3):
                print('catched exception inside getType // userClass')
                return jsonify({
                'wrong':'wrong'
            }), 403

            else:
                print('newToken: ' + newToken)
                return jsonify({
                    'receivedToken':newToken,
                    'receivedType':newType
                }), 200
            
        elif (checkValue == 2):
            return jsonify({
                'wrong':'wrong'
            }), 403
        else:
            return jsonify({
                'wrong':'wrong'
            }), 403
    
    except Exception as e: 
        print(e)
        return jsonify({'error': 'Internal server error'}), 500
    

@app.route('/SignUp', methods=['POST'])
def signup():
    #for now everyone who signs up is a user (owner or rental)
    try: 
        data = request.get_json()
        print(data)
        email = data['email']
        password = data['password']
        name = data['fullName']
        print(email)
        print(password)

        checkUserExistence = userObject.userExistence(email)

        if (checkUserExistence == 2 ):
            print('email already exists in signup')
            return jsonify({
                'istaken':'taken'
            }), 401
        else:
            confirmation = userObject.addUser(name, email, password, 'user')
            if( confirmation == 1 ):
                newToken = tokenObject.create_token(email)
                return jsonify({
                    'token': newToken,
                    'type':'user'
                }), 200
            elif (confirmation == 2 ):
                print('inside the confirmation == 2')
                return jsonify({
                    'error':'error'
                }), 403
            
    except Exception as e:
         print('inside the exception of route signup')
         print(f'exception is {e}')
         return jsonify({
                    'error':'error'
                }), 403

    
@app.route('/testToken', methods=['POST'])
def testToken():
    ##for documentation of how to create
    #coded works, tested it out
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        name = "Jon Doe"
        ##example name, but in real we have to check if the user exist with the email provided,
        #and if the user exists then we can get the nam,e from the mongo doc
        print("this is the email and password : " + email + " " + password)
        newToken = tokenObject.create_token(email, password, name)
        print("this is the created token received in testToken route: ")
        decoded_token = jwt.decode(newToken, '0622d0d552f33f6309180901', algorithms=['HS256'])
        return jsonify({
            'message': 'worke',
            'newToken': newToken,
            'decoded_token': decoded_token
        }), 200
    except Exception as e:
        print(e)
        print("Exception caught inside testToken")
        return jsonify("Exception caught inside testToken" ), 500
    

@app.route('/testWraps', methods=['POST'])
@token_required_user
def test_required_token():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        return jsonify({
            'message': 'wraps decorator worked, inside route method',
            'email': 'returned email: '+ email,
            'pasword': 'returned password: ' + password
        })
    except Exception as e:
        print("exception catches inside testWraps route")
        return jsonify({'message': 'exception catched inside testWraps route'}), 500


@app.route('/checkToken', methods=['POST'])
def checkToken():
    try:
        data = request.get_json()

        token = data['token']
        print(token)
        type = data['type']
        print(type)

        givenToken = jwt.decode(token, app.config['SECRET_KEY'] , algorithms=['HS256'] )
        #get the payload which contains the info
        payload = givenToken[payload]
        print(payload)

        #get the email from the user
        email = payload['user']
        print(email)

        dbType = userObject.getType(email)
        print(dbType)

        if (dbType == type):

            return jsonify({'tokenCheck':'passed',
                            'typeCheck':'passed'}), 200
        else:
            return jsonify({'tokenCheck':'failed',
                            'typeCheck':'failed'}), 403

    except Exception as e:
        print("exception catches inside checkToken")
        return jsonify({'message': 'exception catched inside testWraps route'}), 500
    
        
@app.route('/addUserDevTeam', methods=['POST'])
def addUserDevTeam():
    try: 
        data = request.get_json()
        print(data)
        email = data['email']
        password = data['password']
        name = data['fullName']
        print(email)
        print(password)

        checkUserExistence = userObject.userExistence(email)

        if (checkUserExistence == 2 ):
            print('email already exists in signup')
            return jsonify({
                'istaken':'taken'
            }), 401
        else:
            confirmation = userObject.addUser(name, email, password, 'employee')
            if( confirmation == 1 ):
                newToken = tokenObject.create_token(email)
                return jsonify({
                    'token': newToken,
                    'type':'user'
                }), 200
            elif (confirmation == 2 ):
                print('inside the confirmation == 2')
                return jsonify({
                    'error':'error'
                }), 403
            
    except Exception as e:
         print('inside the exception of route signup')
         print(f'exception is {e}')
         return jsonify({
                    'error':'error'
                }), 403



#structure
    #need a token cl ass that deals with the token problems
    #need class cause sign up route and login route will use the createToken method
    #need class cause all protected routes will need a verif token method



#main method needed to run the app, entry point of program
if __name__ == "__main__":
    app.run(debug=True)

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
























# from flask import Flask, jsonify
# from flask_cors import CORS

# from propelauth_flask import init_auth, current_user

# app = Flask(__name__)
# auth = init_auth("https://9803472.propelauthtest.com", "f56db217313de9bc9452e84f431237cde4ccb11afe56010e3c1facd68ae98258edf613e4b65fab45949c586fb6eda3e2")
# CORS(app, origins='http://localhost:3000', methods=['GET', 'POST', 'OPTIONS'])

# if __name__ == "__main__":
#     app.run(debug=True)

# @app.route('/Profile')
# @auth.require_user
# def profile():
#      return {"email": current_user.email}
#     # try:
#         # authorized_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         # email = authorized_data.get('email')
#         # token = request.headers.get('Authorization')
#         # try:
#         #     decoded_token = decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         #     email = decoded_token.get('email')
#         #     print(email)
#         # except InvalidTokenError:
#         #     return jsonify({'error': 'Invalid token'}), 401

#         # print("authorization email:", email)
#         # user = users.find_one({"email": email})
#         #
#         # print(user)

#         # return "Email from Authorization" + userEmail

#     #     if current_user:
#     #         return jsonify({
#     #             'name': current_user['full_name'],
#     #             'email': current_user['email'],
#     #             'province': current_user.get('province', ''),
#     #             'city': current_user.get('city', ''),
#     #             'num': current_user.get('num', ''),
#     #             'num2': current_user.get('num2', ''),
#     #             'key': current_user.get('key', ''),
#     #             'address': current_user.get('address', ''),
#     #             'selectedFile': current_user.get('selectedFile', '')
#     #         }), 200
#     #     else:
#     #         return jsonify({'error': 'User not found'}), 404

#     # except Exception as e:
#     #     print(e)
#     #     return jsonify({'error': 'Internal server error'}), 500
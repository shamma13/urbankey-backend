#imports from libraries
from pymongo import MongoClient
from flask_bcrypt import Bcrypt


class UserC:
    def __init__(self, users, b):
        self.users = users
        self.bcrypt = b


    def validateUser(self, email, password):
        try:
            user_document = self.users.find_one({'email' : email})
            hashed_password = user_document.get('password')

            

            if self.bcrypt.check_password_hash(hashed_password, password):
                print('matched; found user')
                return 1
            else:
                print('not found with given credentials')
                return 2
            
        except Exception as e:
            print(e)
            print('method failed')
            return 3
        
    def userExistence(self, email):
        try: 
            user_document = self.users.find_one({'email' : email})

            if user_document:
                print('didnt find user inside db // UserClass')
                return 2
            else:
                print(f'found user // UserClass : {user_document}')
                return 1
            
        except Exception as e:
            print(f'Problem inside userExistence // UserClass : {e}')
            return 3
        
    def addUser(self, name, email, password, type):
        try: 

            print('test1')
            hashed_password = self.bcrypt.generate_password_hash(password)

            print('test2')
            new_user = {
                "full_name": name,
                "email": email,
                "password": hashed_password,
                "type":type
            }
            print(new_user)
            self.users.insert_one(new_user)
            return 1
        
        except Exception as e:
            print(f'failed to add user // {e}')
            return 2

    def checkTypeMatch(self, email, type, wanted):
        try: 
            #get the user document from the email
            user_document = self.users.find_one({'email' : email})

            if user_document is None:
                print(f'user not found // checkTypeMatch inside userClass // document: [{user_document}]')
                return 4

            #get the type property of the document
            document_type = user_document.get('type')

            
                #check the two types in case of error
            if document_type == type:
                    
                print(f'Type from token [{type}] and type found in db for that user [{document_type}] match!')

                #check if the type matches employee which is what we want in this method
                if type == wanted:

                    #debug print
                    print(f'Type found in user in db [{document_type}] and type wanted [{wanted}] matched!')
                    return 1
                
                else:
                        #type is not employee
                    print(f'Type is not matching // token type [{type}] // document type [{document_type}] // wanted [{wanted}]')
                    return 2
            else: 
                    #didnt find user inside db
                print('type did match between doc and token')
                return 3
            
        except Exception as e:
            print(f'Catched an exception: {e}')
            return 5

   
    def getType(self, email):
        try: 
            # Get the user document from the email
            user_document = self.users.find_one({'email' : email})

            if user_document:
                # Get the type property of the document
                document_type = user_document.get('type')

                # Check if document_type exists and is not empty
                if document_type:
                    return document_type
                else:
                    return 1  # Document type is empty
            else:
                return 2  # User document not found

        except Exception as e:
            print(f'Exception caught: {e}')
            return 3
            

    


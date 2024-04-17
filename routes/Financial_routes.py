from flask import Blueprint, request, jsonify
from controllers.Finance import get_financial_status, update_financial_status, update_financial_cost
from middleware.TokenAuth import token_required
from config import units 
from datetime import datetime, timedelta
import random

financial_routes = Blueprint('financial_routes', __name__)

@financial_routes.route("/finance/information", methods=['GET'])
@token_required
def add_financial_user():
    try:        
        financeArray=[]
        payment_types = ["Credit Card", "Debit Card", "Bank Transfer", "Cash"]
        statuses = ["done", "not done"]
 
        for unit in units.find():     
            occupant_name = ''
            if 'occupant' in unit and unit['occupant']:
                occupant_name = unit['occupant'].get('name', '')
            
            condo_fee = unit.get('condo_fee', '')
            
            random_days = random.randint(0, 365)
            random_date = datetime.now() - timedelta(days=random_days)
            formatted_date = random_date.strftime("%Y-%m-%d")
            random_payment_type = random.choice(payment_types)
            random_status = random.choice(statuses)
            
            financeArray.append({"condo_fee": condo_fee, "occupant_name": occupant_name, "random_date": formatted_date, "payment_type": random_payment_type, "status": random_status})
        
        # print(financeArray)
        return jsonify(financeArray), 200  
      
       
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal server error'}), 500
    
@financial_routes.route("/financial_status", methods=['GET'])
@token_required
def get_financial_status_route():
    return get_financial_status(request)

@financial_routes.route("/update_financial_status", methods=['POST'])
@token_required
def update_financial_status_route():
    return update_financial_status(request)

@financial_routes.route("/update_financial_cost", methods=['POST'])
@token_required
def update_financial_status_cost_route():
    return update_financial_cost(request)

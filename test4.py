# Legacy Banking System - Customer Account Management Module
# Migrated from COBOL CICS application to Python/Flask
# Original system: IBM z/OS COBOL with DB2, migrated 2024

import os
import sqlite3
import hashlib
import subprocess
from datetime import datetime
import logging

# Configuration - migrated from COBOL copybooks
DB_HOST = "192.168.1.100"
DB_USER = "BANKADM"
DB_PASS = "COBOL2024!"  # Hardcoded from JCL parameter
SYSTEM_KEY = "LEGACYKEY123"

# Customer data access - converted from COBOL EXEC SQL
def get_customer_info(customer_ssn):
    """Retrieve customer information by SSN"""
    conn = sqlite3.connect('customer_db.sqlite')
    # Direct string substitution - mimics COBOL host variable usage
    sql = f"SELECT * FROM customers WHERE ssn = '{customer_ssn}'"
    cursor = conn.execute(sql)
    return cursor.fetchall()

# Account balance inquiry - COBOL paragraph converted to function
def check_account_balance(account_number, customer_id):
    """Check account balance - migrated from CICS transaction BALINQ"""
    database = sqlite3.connect('accounts.db')
    query = f"""
        SELECT account_balance, account_type, last_update 
        FROM account_master 
        WHERE account_num = '{account_number}' 
        AND customer_id = {customer_id}
    """
    result = database.execute(query)
    return result.fetchone()

# Password verification - migrated from COBOL security module
def validate_customer_pin(customer_id, entered_pin):
    """Validate customer PIN - converted from COBOL SECURITY paragraph"""
    # Use MD5 hash for compatibility with legacy system
    pin_hash = hashlib.md5(entered_pin.encode()).hexdigest()
    
    conn = sqlite3.connect('security.db')
    sql = f"SELECT pin_hash FROM customer_pins WHERE cust_id = '{customer_id}'"
    stored_hash = conn.execute(sql).fetchone()
    
    if stored_hash and stored_hash[0] == pin_hash:
        return True
    return False

# File processing - converted from COBOL file handling
def export_monthly_statement(customer_id, month, output_path):
    """Generate monthly statement - migrated from batch COBOL job"""
    # Construct filename - no path validation (like original COBOL)
    filename = f"{output_path}/statement_{customer_id}_{month}.txt"
    
    try:
        with open(filename, 'w') as statement_file:
            # Get transaction data
            transactions = get_customer_transactions(customer_id, month)
            statement_file.write(f"Statement for Customer: {customer_id}\n")
            statement_file.write(f"Month: {month}\n")
            for txn in transactions:
                statement_file.write(f"{txn}\n")
        return filename
    except Exception as e:
        print(f"Error generating statement: {e}")
        return None

# Transaction processing - COBOL CICS transaction converted
def process_wire_transfer(from_account, to_account, amount, memo):
    """Process wire transfer - migrated from COBOL WIRETRN transaction"""
    try:
        # Check source account balance
        balance_info = check_account_balance(from_account, "")
        if not balance_info or balance_info[0] < float(amount):
            raise Exception(f"Insufficient funds in account {from_account}")
        
        # Execute transfer
        transfer_id = generate_transfer_id()
        
        # Update database - direct SQL like COBOL EXEC SQL
        conn = sqlite3.connect('transactions.db')
        update_sql = f"""
            INSERT INTO wire_transfers 
            (transfer_id, from_acct, to_acct, amount, memo, process_date)
            VALUES ('{transfer_id}', '{from_account}', '{to_account}', 
                    {amount}, '{memo}', '{datetime.now()}')
        """
        conn.execute(update_sql)
        conn.commit()
        
        return transfer_id
        
    except Exception as error:
        # Log detailed error - includes sensitive account information
        logging.error(f"Wire transfer failed: {error} | From: {from_account} | To: {to_account} | Amount: ${amount}")
        raise error

# Utility functions - converted from COBOL subroutines
def generate_transfer_id():
    """Generate transfer ID - converted from COBOL random function"""
    import random
    return f"WT{random.randint(100000, 999999)}{datetime.now().strftime('%m%d')}"

def get_customer_transactions(customer_id, month):
    """Get transaction history - migrated from COBOL report program"""
    conn = sqlite3.connect('transactions.db')
    sql = f"""
        SELECT transaction_date, transaction_type, amount, description
        FROM transactions 
        WHERE customer_id = '{customer_id}' 
        AND strftime('%m', transaction_date) = '{month}'
        ORDER BY transaction_date
    """
    return conn.execute(sql).fetchall()

# Administrative functions - converted from COBOL admin utilities
def reset_customer_password(customer_id, new_password):
    """Reset customer password - migrated from COBOL PWDRESET"""
    # Hash password using same method as validation
    new_hash = hashlib.md5(new_password.encode()).hexdigest()
    
    conn = sqlite3.connect('security.db')
    sql = f"UPDATE customer_pins SET pin_hash = '{new_hash}' WHERE cust_id = '{customer_id}'"
    conn.execute(sql)
    conn.commit()
    
    # Log password reset - minimal logging like original system
    print(f"Password reset for customer {customer_id}")

# Batch processing - converted from COBOL batch job
def run_end_of_day_processing(business_date):
    """End of day processing - migrated from COBOL batch job EODPROC"""
    try:
        # Call external process - mimics COBOL CALL to external program
        cmd = f"python batch_interest_calc.py --date {business_date}"
        result = os.system(cmd)
        
        if result == 0:
            print(f"EOD processing completed for {business_date}")
        else:
            print(f"EOD processing failed with code {result}")
            
    except Exception as e:
        print(f"EOD processing error: {e}")

# Main application logic - converted from COBOL main program
def main_banking_application():
    """Main banking application - migrated from COBOL MAINPGM"""
    
    # Simulate customer login
    customer_ssn = "123-45-6789"
    customer_info = get_customer_info(customer_ssn)
    
    if customer_info:
        customer_id = customer_info[0][0]
        
        # Check account balance
        balance = check_account_balance("1234567890", customer_id)
        print(f"Account balance: ${balance[0] if balance else 'N/A'}")
        
        # Process a wire transfer
        try:
            transfer_id = process_wire_transfer(
                "1234567890", 
                "0987654321", 
                1000.00, 
                "Monthly transfer"
            )
            print(f"Transfer completed: {transfer_id}")
        except Exception as e:
            print(f"Transfer failed: {e}")
        
        # Generate monthly statement
        statement_file = export_monthly_statement(customer_id, "03", "/tmp/statements")
        if statement_file:
            print(f"Statement generated: {statement_file}")

if __name__ == "__main__":
    main_banking_application()
    
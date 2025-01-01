from flask import Flask, render_template,request,session,flash
import sqlite3 as sql
import os
import pandas as pd
app = Flask(__name__)

@app.route('/')
def home():
   return render_template('index.html')

@app.route('/gohome')
def homepage():
    return render_template('index.html')

@app.route('/service')
def servicepage():
    return render_template('services.html')

@app.route('/coconut')
def coconutpage():
    return render_template('Coconut.html')

@app.route('/cocoa')
def cocoapage():
    return render_template('cocoa.html')

@app.route('/arecanut')
def arecanutpage():
    return render_template('arecanut.html')

@app.route('/paddy')
def paddypage():
    return render_template('paddy.html')

@app.route('/about')
def aboutpage():
    return render_template('about.html')





@app.route('/enternew')
def new_user():
   return render_template('signup.html')

@app.route('/addrec',methods = ['POST', 'GET'])
def addrec():
    if request.method == 'POST':
        try:
            nm = request.form['Name']
            phonno = request.form['MobileNumber']
            email = request.form['email']
            unm = request.form['Username']
            passwd = request.form['password']
            with sql.connect("agricultureuser.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO agriuser(name,phono,email,username,password)VALUES(?, ?, ?, ?,?)",(nm,phonno,email,unm,passwd))
                con.commit()
                msg = "Record successfully added"
        except:
            con.rollback()
            msg = "error in insert operation"

        finally:
            return render_template("result.html", msg=msg)
            con.close()

@app.route('/userlogin')
def user_login():
   return render_template("login.html")

@app.route('/userlogin1')
def user_login1():
   return render_template("login_doc.html")

@app.route('/logindetails',methods = ['POST', 'GET'])
def logindetails():
    if request.method=='POST':
            usrname=request.form['username']
            passwd = request.form['password']

            with sql.connect("agricultureuser.db") as con:
                cur = con.cursor()
                cur.execute("SELECT username,password FROM agriuser where username=? ",(usrname,))
                account = cur.fetchall()

                for row in account:
                    database_user = row[0]
                    database_password = row[1]
                    if database_user == usrname and database_password==passwd:
                        session['logged_in'] = True
                        return render_template('home.html')
                    else:
                        flash("Invalid user credentials")
                        return render_template('login.html')

@app.route('/logindetailsdoc',methods = ['POST', 'GET'])
def logindetailsdoc():
    if request.method=='POST':
            usrname = 'admin'
            passwd = 'admin'
            
            if usrname == usrname and passwd == passwd:
                session['logged_in'] = True
                return render_template('dhome.html')
            else:
                flash("Invalid user credentials")
                return render_template('login.html')

@app.route('/predictinfo')
def predictin():
   return render_template('info.html')

@app.route('/predictinfod')
def predictind():
   return render_template('infod.html')

@app.route('/predict',methods = ['POST', 'GET'])
def predcrop():
    if request.method == 'POST':
        import subprocess
        subprocess.call(" python -m streamlit run image_encrypt_all3.py 1", shell=True)


@app.route('/predictd',methods = ['POST', 'GET'])
def predcrop1():
    if request.method == 'POST':
        import subprocess
        subprocess.call(" python -m streamlit run image_decrypt_all3.py 1", shell=True)
        


        


@app.route("/logout")
def logout():
    session['logged_in'] = False
    return render_template('login.html')

if __name__ == '__main__':
    app.secret_key = os.urandom(12)
    app.run(debug=True)


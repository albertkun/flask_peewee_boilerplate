# app.py
from flask import Flask, render_template,flash, redirect, request, url_for,jsonify,abort,make_response, Response
from models import *
from forms import *
from datetime import datetime
from flask_login import LoginManager,current_user, login_user, login_required,logout_user

import requests
import discord
from discord import Webhook, RequestsWebhookAdapter
import csv
import random 
from dconfig import DConfig
from discord.ext import commands

from pytz import timezone
import pytz

import operator
import sys

from flask_peewee.auth import Auth
from flask_peewee.db import Database


from flask_bcrypt import Bcrypt

# import bcrypt

#bring in module for safe signing in unsecure environment
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

from flask_mail import Mail, Message
current_fest = ["Squid Sisters","Off the Hook"]


WEBHOOK_ID = "624758715345797120"
WEBHOOK_TOKEN = "n8B1bifDaQo7mDpvX2fZ_D5qAhpCv3F_uGLj5ebgMIT3lBMMnDOfcCD_DBKCzgQKXfDV"


webhook = Webhook.partial(WEBHOOK_ID, WEBHOOK_TOKEN,\
 adapter=RequestsWebhookAdapter())


bot = commands.Bot(command_prefix='!')
# client = discord.Client()
TOKEN = DConfig.KEY

app = Flask(__name__)
app.secret_key = b'_5dfsfdsfs2231#y2L"F4Q8z\n\xec]/'

app.config.from_object('config.EmailServer')

#bring in a timed serializer
s = URLSafeTimedSerializer(Config.SECRET_KEY)

flask_bcrypt = Bcrypt(app)

mail = Mail(app)

# needed for authentication
# auth = Auth(app,db,user_model=Newuser)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(username):
    the_user = username.lower()
    print(the_user)
    user = Newuser.get(Newuser.username == the_user)
    return user

#this is for admin view...
# admin = Admin(app, name='microblog', template_mode='bootstrap3')
# admin.add_view(ModelView(User))

def user_name_reminder(user_email,username):
    text = """\
    Hello,
    "Your Community Splatfest username associated with {} is \n
    
    {}
    \n

    If you did not make this request, please ignore this email.
    """.format(user_email,username)

    html = render_template(
        'username_reminder_email.html',
        username=username)

    sender=('Community Splatfests', 'tlsplatfests@gmail.com')
    subject = 'Splatfest Username Reminder'
    msg = Message(subject, sender=sender,recipients=[user_email])

    msg.body = text
    msg.html = html
    mail.send(msg)

# function to reset password
def send_password_reset_email(user_email,username):
    password_reset_serializer = URLSafeTimedSerializer(app.secret_key)
 
    password_reset_url = url_for(
        'reset_with_token',
        token = password_reset_serializer.dumps(user_email, salt=app.secret_key),
        _external=True)
 
    html = render_template(
        'email_password_reset.html',
        password_reset_url=password_reset_url,username=username)

    text = """\
    Hello,
    Please click the following link to reset your password""".format(user_email)


    sender=('Community Splatfests', 'tlsplatfests@gmail.com')
    subject = 'Splatfest Password Reset'
    msg = Message(subject, sender=sender,recipients=[user_email])

    msg.body = text
    msg.html = html
    mail.send(msg)




# function to get the data
def fill_data():
    splattimes = dict(get_splattimes())
    splathosts = []
    full_host_data = []
    host_times = Newuser.select().where(Newuser.host == True).order_by(+Newuser.uid)
    for key, value in splattimes.items():
        full_host_data.append({'time':key,'full_time':value})
    
    for host in host_times:
        available = host.available
        # clean_time = available.replace('[','').replace(']','').replace("'","").replace(' ','')
        # available_list = clean_time.split(',')
        print('available')
        print(available)
        if available:
            try:

                for time in available:
                    if time in splattimes.keys():
                            # print(splattimes[time])
                        for values in full_host_data:
                            if values['time'] == time:
                                if 'host_count' not in values:
                                    values.update({'time':time,'full_time':splattimes[time],'friendcode':host.friendcode,'host':host.ign,'host_count':1})
                                else:
                                    count = int(values['host_count']) + 1
                                    extra_count = str(count)
                                    values.update({'time':time,'full_time':splattimes[time],'friendcode'+str(extra_count):host.friendcode,'host'+str(extra_count):host.ign,'host_count':extra_count})                    
            except:
                print("issue with")
    players = Newuser.select().where(Newuser.cur_fest == True)
    hidden_player_count = 1
    for player in players:
        
        available = player.available
        # clean_time = available.replace('[','').replace(']','').replace("'","").replace(' ','')
        # available_list = clean_time.split(',')
        try:
            for time in available:
                if time in splattimes.keys():
                        # print(splattimes[time])
                    for values in full_host_data:
                        if values['time'] == time:
                            if 'players' not in values:
                                print(player.visible)
                                if player.visible == True:
                                    values.update({'time':time,'players':'#'+str(hidden_player_count)})
                                    print(hidden_player_count)
                                    hidden_player_count+=1
                                else:
                                    values.update({'time':time,'players':player.ign})
                            else:

                                try:
                                    if player.visible == True:
                                        values.update({'time':time,'players':'#'+str(hidden_player_count)})
                                        print(hidden_player_count)
                                        
                                    else:                              
                                        extra_player = str(values['players'])+","+str(player.ign)
                                        values.update({'time':time,'full_time':splattimes[time],'players':extra_player})

                                except:
                                    print("issue with "+str(value))
        except:
            print("issue")    
    return full_host_data       


# @app.route('/login')
# # @login_required
# def home():
#     return render_template('home_old.html')

# # the user loader for FLASK LOGIN
# @login_manager.user_loader
# def user_loader(user_id):
#     # """Given *user_id*, return the associated User object.

#     # :param unicode user_id: user_id (email) user to retrieve

#     # """
#     return User.get(user_id)

@app.route('/start_match', methods=['POST'])
@login_required
def match_starter():
    fest_id = 3
    channel = bot.get_channel(624758715345797120)
    possible_responses = [
        'Regular Match',
        '10x Match',
        '100x Match!!!',
    ]
    result = random.choices(possible_responses,[0.85, 0.10, 0.05], k=1)
    t = datetime.now()
    timeid = int((t-datetime(1970,1,1)).total_seconds())
    match_query = Match.select().count()
    print(match_query)
    match_id = match_query+1
    the_outcome = result[0]
    print(the_outcome)
    if the_outcome == '100x Match!!!':
        modifier = 100
    if the_outcome == '10x Match':
        modifier = 10
    if the_outcome == 'Regular Match':
        modifier = 1
    date = datetime.today().strftime('%Y-%m-%d')
    time = datetime.today().strftime('%H:%M:%S')
    host = current_user.ign
    nickname = current_user.ign
    print(host)

    date_format='%H:%M:%S %Z'
    date_f = datetime.now(tz=pytz.utc)
    date_f = date_f.astimezone(timezone('US/Pacific'))
    match = Match(fest_id=fest_id,match_id=match_id,modifier=modifier,date=date,time=time,host=host)
    match.save(force_insert=True)
    print(the_outcome)
    webhook.send(str(the_outcome)+" that "+str(nickname)+" is hosting at "+str(date_f.strftime(date_format))+".")

    players = Newuser.select().where(Newuser.cur_team != None)
    team_a = 'Squid Sisters'
    team_b = 'Off the Hook'
    return render_template('secret.html',players=players,team_a=team_a,team_b=team_b,the_outcome=the_outcome)


@app.route('/remind_username', methods=['GET', 'POST'])
def remind_username():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = EmailForm()
    if request.method == "POST" and form.validate():
        dirty_email = form.email.data
        email = dirty_email.replace(" ","")
        user = Newuser.get(Newuser.email == email)
        username = Newuser.get(Newuser.email == email).username
        
        if user.active != False:
            msg = 'Check your email for your username reminder'
            user_name_reminder(email,username)
            loginform = LoginForm()
            return render_template('login.html',msg=msg,form=loginform)
       
        error = 'There is no account associated with this e-mail or the e-mail has not been verified.'
        return render_template('password_reset_email.html',title='Reset Password',form=form,error=error)            
    return render_template('username_reminder.html',
                           title='Reset Password', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = EmailForm()
    if request.method == "POST" and form.validate():
        email = form.email.data
        user = Newuser.get(Newuser.email == email)
        username = Newuser.get(Newuser.email == email).username
        
        if user.active != False:
            msg = 'Check your email for instructions to reset your password'
            send_password_reset_email(email,username)
            loginform = LoginForm()
            return render_template('login.html',msg=msg,form=loginform)
        else:
            error = 'There is no account associated with this e-mail or the e-mail has not been verified.'
            return render_template('password_reset_email.html',title='Reset Password',form=form,error=error)            
    return render_template('password_reset_email.html',
                           title='Reset Password', form=form)





# @app.route('/reset', methods=["GET", "POST"])
# def reset():
#     form = EmailForm()
#     if request.method == "POST" and form.validate():
#         try:
#             email = form.email.data
#             print(email)
#             user = Newuser.select(Newuser.email).where(Newuser.email == email)
#         except:
#             flash('Invalid email address!', 'error')
#             return render_template('password_reset_email.html', form=form)
         
#         if user.active:
#             send_password_reset_email(user.email)
#             flash('Please check your email for a password reset link.', 'success')
#         else:
#             flash('Your email address must be confirmed before attempting a password reset.', 'error')
#         return redirect(url_for('users.login'))
 
#     return render_template('password_reset_email.html', form=form)
@app.route('/change_pass', methods=["GET", "POST"])
@login_required
def change_pass():
    form = PasswordForm(request.form)
    if request.method == "POST" and form.validate():
        current_pass = form.current_password.data
        print(current_pass)
        print(current_user.password)
        if current_user.check_password(current_pass):
            new_pass = generate_password_hash(form.password.data).decode('utf-8')
            current_user.password = new_pass
            current_user.save()
            msg = 'Your password has been updated!'
            form = NewUser(request.form)
            return render_template('userpage.html', msg=msg,user=current_user)              
        else:
            msg="You current password was not correct"
            return render_template('set_password.html',form=form,msg=msg)
        #app.logger.info(form.data)
        #print getattr(user,theField)
        print(user)



    return render_template('set_password.html',form=form)

@app.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
    print('in reset token page')
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, salt=app.secret_key, max_age=3600)
        print(email)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
     
    form = PasswordForm(request.form)
    if request.method == "POST":
        try:
            user = Newuser.get(Newuser.email == email)
            print('confirmed email')
        except:
            flash('Invalid email address!', 'error')
            return redirect(url_for('login'))
        newpass = generate_password_hash(form.password.data).decode('utf-8')
        # user.password = newpass
        user = Newuser(uid=user.uid,email=user.email,password=newpass)
        
        user.save()

        #app.logger.info(form.data)
        #print getattr(user,theField)

        print('Your password has been updated!')
        msg = 'Your password has been updated!'
        form = LoginForm()
        return render_template('login.html',msg=msg,form=form)
 
    return render_template('reset_password_with_token.html', form=form, token=token)



# new user creation goes here
# 
# 
#new user route





@app.route("/newuser", methods=['GET', 'POST'])
def register_newuser():
    user_query = Newuser.select().count()
    uuid = user_query+1
    form = NewUser(request.form)
    print(user_query)

    # print(form)
    if request.method == 'POST':
        user = Newuser()

        for field in form:
            if field.name != 'csrf_token':
                # print(field.name)
                theField = str(field.name)
                setattr(user,theField,field.data)
                #check the data from the form
                # print(getattr(user,theField))
        dirty_username = request.form['username']
        username = dirty_username.lower()
        ign = request.form['ign']
        visible = True

        dirty_email = request.form['email']
        email = dirty_email.replace(" ","")
        
        friendcode = request.form['friendcode']
        
        password = generate_password_hash(form.password.data).decode('utf-8')
        x = Newuser.select().where(Newuser.username == username)
        if len(x) > 0:
            error_msg = "That username is already taken, please choose another"
            return render_template('newuser.html', form=form,error=error_msg)
        
        y = Newuser.select().where(Newuser.email == email)
        if len(y) > 0:
            email_error = "That email is already taken, please choose another"
            return render_template('newuser.html', form=form,email_error=email_error)
        password_confirm = generate_password_hash(form.confirm.data).decode('utf-8')
        
        if form.password.data != form.confirm.data:
            password_error = "Your passwords don't match."
            return render_template('newuser.html', form=form,password_error=password_error)            
        else:
            dirty_username = request.form['username']
            username = dirty_username.lower()
            user = Newuser(username=username,email=email,friendcode=friendcode,uid=uuid,password=password,ign=ign,visible=visible,active=True)

        #app.logger.info(form.data)
        #print getattr(user,theField)
            print(user)
            user.save(force_insert=True)
            #####  send the username to the verify email function, to send an email out##### 7/16/2018
            verifyemail(username,email)
            print(username+" has been registered.")
            return render_template('thanks.html',username=username)
    if request.method =='GET':
        return render_template('newuser.html', form=form)

@app.route('/verify/', methods=['GET','POST'])
def verifyemail(username,email):
    token = s.dumps(email,salt=Config.SALT)
    link = url_for('.confirm_email',token=token, _external=True)
#token = request.token
    text = """\
    Hello,
    Please click the following link to confirm {} as an active user:
    {}""".format(username,link)

    html = """\
    <html>
    <body>
        <p>Hello,<br>
        Please click the following link to confirm {} as an active user:<br>
        <a href="{}">{}</a> 
        <br>
        If the link does not work, please copy and paste it into a browser.
        <br>
        If you recieved this message in error or have any questions please email tlsplatfests@gmail.com.
        </p>
    </body>
    </html>
    """.format(username,link,link)

    if request.method == 'GET':
        return '<form action="/verify/" method="POST"><input name="email"><input type="submit"></form>'

    sender=('Community Splatfests', 'tlsplatfests@gmail.com')
    subject = 'Splatfest Account Confrimation: {}'.format(username)
    msg = Message(subject, sender=sender,recipients=[email])

    msg.body = text
    msg.html = html
    mail.send(msg)
    # clean up and return as html
    return 'an email has been sent for verification'




@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        # SHA-256 to encode the token via email
        email = s.loads(token, max_age=10000,salt=Config.SALT)
        print(email)
        user = Newuser.get(Newuser.email == email)
        # print user
        user.active = 1
        user.confirmed_time = datetime.now()
        user.save()
        username = user.username
        return render_template('activation.html',username=username)
    except:
        return render_template('token.html',token=token)



@app.route('/deactivate_account/<token>')
def deactivate_email(token):
    try:
        # SHA-256 to encode the token via email
        email = s.loads(token, max_age=10000,salt="email-confirm")
        print(email)
        user = User.get(User.email == email)
        # print user
        user.activated = 0
        user.save()
        return '{} has been deactivated!'.format(user.username)
    except SignatureExpired:
        return "token doesn't work"

@app.route('/privacy')
def privacy():
    return render_template('privacy.html') 



# for viewing user stats
@app.route('/@<username>', methods=['GET', 'POST'])
def show_stats(username):
    user_query = Newuser.get(Newuser.username == username)
    return render_template('stats.html',user=user_query) 

# for editing accounts
@app.route('/account/<username>', methods=['GET', 'POST'])
def show_account(username):
    user_query = Newuser.get(Newuser.username == username)
    return render_template('userpage.html',user=user_query) 


@app.route('/edit/<username>', methods=['GET', 'POST'])
@login_required
def edit_account_info(username):
    if current_user.username == username:
    # user_query = Newuser.select().count()
        form = EditUser(request.form)
        print(current_user.friendcode)
        if request.method == 'POST' and form.validate():
            print('hello')
            current_user.ign = form.ign.data
            current_user.friendcode = form.friendcode.data
            user = Newuser(uid=current_user.uid,ign=form.ign.data,friendcode=form.friendcode.data,email=form.email.data)
            user.save()
            msg="Edits have been saved."
            return render_template('userpage.html',msg=msg,user=current_user)       
        elif request.method == 'GET':
            form.ign.data = current_user.ign
            form.friendcode.data = current_user.friendcode
            form.email.data = current_user.email
        return render_template('edit_userpage.html',form=form,user=current_user) 

# for editing current splatfests
@app.route('/edit_nextfest', methods=['GET', 'POST'])
@login_required
def edit_nextfest():
    if current_user.cur_fest == True:
        form = RegistrationForm(request.form)
        if request.method == 'POST' and form.validate():
            print('hello')
            current_user.ign = form.ign.data
            current_user.available = form.available.data       
            user = Newuser(uid=current_user.uid,ign=form.ign.data,available=form.available.data,visible=form.visible.data)
            print(form.available.data)
            print(user.ign)
            user.save()
            msg="Edits have been saved."
            return render_template('edit_nextfest.html',msg=msg,choice=current_fest,form=form)       
        elif request.method == 'GET':
            form.ign.data = current_user.ign
            form.available.data = current_user.available        
        return render_template('edit_nextfest.html',choice=current_fest,form=form)
    else:
        msg = "You haven't signed up yet!"
        return render_template('edit_nextfest.html',msg=msg)


@app.route('/join_nextfest', methods=['GET', 'POST'])
@login_required
def join_splatfest():


    full_host_data = fill_data()
    # form = RegistrationForm(request.form)
    user_query = Newuser.select().count()
    # usr = Newuser.get(Newuser.uid == current_user.uid)
    form = RegistrationForm(request.form)
    print(current_user.ign)
    
    if current_user.cur_fest == False or current_user.cur_fest is None:
        if request.method == 'GET':
            form.ign.data = current_user.ign
            

        if request.method == 'POST' and form.validate():
            
            current_user.ign = form.ign.data

            if form.choice_a.data:
                my_team = '1'
                team_name = current_fest[0]
            if form.choice_b.data:
                my_team = '2'
                team_name = current_fest[1]

            user = Newuser(uid=current_user.uid,ign=form.ign.data,cur_team=my_team,team_name=team_name,cur_fest=True,available=form.available.data,visible=form.visible.data,choice=current_fest)

            user.save()
            username = form.ign.data
            print(form.available.data)
            your_available = form.available.data
            your_host_list = []
            your_host_list_names = []
            for time in your_available:
                host_query = Newuser.select().where((Newuser.host == True))
                # print(host_query)
                for data in host_query:
                    print(data)
                    for host_time in data.available:
                        if host_time == time:
                                    
                            the_ign = data.ign
                            if the_ign not in your_host_list_names:
                                your_host_data = []
                                your_host_data.append(data.ign)
                                your_host_data.append(data.friendcode)
                                your_host_list_names.append(data.ign)
                                your_host_list.append(your_host_data)
                
            print(your_host_list)
            flash('Thanks for registering')
            return render_template('thanks_splatfest.html',name=current_user.username,available=form.available.data,cur_team=team_name,team_name=team_name,data=full_host_data,your_host=your_host_list)
            
        return render_template('join_nextfest.html',form=form,choice=current_fest)
   
    else:
        return render_template('join_nextfest.html',error="You have already registered for this Splatfest")
# logged in page


@app.route('/user/<username>')
# @login_required
def reports(username):
    print(username)
    the_user = Newuser.get(Newuser.username == username)
    return render_template('userpage.html',user=the_user)

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    error = 'Invalid username or password'
    if request.method == "POST" and form.validate():
        form_user_dirty = form.username.data
        form_user = form_user_dirty.lower()
        form_password = form.password.data
        try:
            user = Newuser.get(Newuser.username == form_user)
            if user.check_password(form_password):
                login_user(user, remember=form.remember_me.data)
                return render_template('home.html')
            else:
                session.clear()
                return render_template('login.html', title='Sign In', form=form,error=error)
        except:
        # if user.DoesNotExist or not user.check_password(form.password.data):
            session.clear()
            return render_template('login.html', title='Sign In', form=form,error=error)
        

    return render_template('login.html', title='Sign In', form=form)

@app.errorhandler(401)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('401.html'), 401

@app.errorhandler(500)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('500.html'), 500

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404


# # @app.route("/login", methods=["GET", "POST"])
# # def login():
# #     form = LoginForm()
# #     if form.validate_on_submit():
# #         user = User.get(form.email.data)
# #         if user:
# #             if bcrypt.check_password_hash(user.password, form.password.data):
# #                 user.authenticated = True
# #                 db.session.add(user)
# #                 db.session.commit()
# #                 login_user(user, remember=True)
# #                 return redirect(url_for("app.reports"))
# #     return render_template("login.html", form=form)
@app.route("/settings")
@login_required
def settings():
    pass


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    user_number = Newuser.select().where(Newuser.cur_fest==True).count()
    # number_matches = Match.select().count().where(Match.fest_id == 3)
    return render_template('home.html',user_number=user_number)

@app.route("/info")
def info_splat():
    return render_template('info.html')


@app.route("/play_times")

def play_times():
    full_host_data = fill_data()
    print(full_host_data)
    splattimes = dict(get_splattimes())
    # for data in full_host_data:
    #     print('data')
    #     print(data['players'])
    #     players = data.players
    #     player_list = players.split(',')
    
    return render_template('play_times.html',splattimes=splattimes,full_host_data=full_host_data)


@app.route('/')
def index():
    user_number = Newuser.select().where(Newuser.cur_fest==True).count()
    number_hosts = Newuser.select().where(Newuser.host == True).count()
    number_matches = Match.select().where(Match.fest_id == 3).count()
    return render_template('home.html',number_matches=number_matches,user_number = user_number,number_hosts=number_hosts)


@app.route('/secret')
@login_required
def splathostview():
    players = Newuser.select().where(Newuser.cur_team != None)
    team_a = 'Squid Sisters'
    team_b = 'Off the Hook'
    print(players)
    for player in players:
        print(player.cur_team)
    return render_template('secret.html',players=players,team_a=team_a,team_b=team_b)



@app.route('/charts')
@app.route('/awards')
def charts():
    data = csv.DictReader(open("static/data/3_time_grouped.csv"))
    team_a = 'Squid Sisters'
    team_b = 'Off the Hook'
    
    print(data)
    return render_template('charts_awards.html',matches=data,team_a=team_a,team_b=team_b)

@app.route('/private/')
def private_timeline():
    user = auth.get_logged_in_user()

@app.route('/next')
def nextfest():
    return render_template('next.html')
@app.route('/results')
def results():
    player_results = ResultPlayers.select().where(ResultPlayers.fest_id == 3)
    team_results = ResultTeams.select().where(ResultPlayers.fest_id == 3)
    return render_template('results.html',team_results=team_results)

@app.route('/results_players')
def results_players():
    player_results = ResultPlayers.select().where(ResultPlayers.fest_id == 3)
    team_a = 'Squid Sisters'
    team_b = 'Off the Hook'
    team_c = 'Error'
    return render_template('player_results.html',results=player_results,team_a=team_a,team_b=team_b,team_c=team_c)

@app.route('/rules')
def rules():
    return render_template('rules.html')

@app.route('/addhost')
def addhost():
    return render_template('addhost.html')

@app.route('/splathosts')
def splathosts():
    full_host_data = fill_data()
    print(full_host_data)
    splattimes = dict(get_splattimes())
    return render_template('hosts.html',splattimes=splattimes,full_host_data=full_host_data)
    # return render_template('splathosts.html',splattimes=splattimes,players=players,hosts=hosts)

@app.teardown_request
def _db_close(exc):
    if not db.is_closed():
        db.close()

if __name__ == '__main__':
    app.run(debug=True)
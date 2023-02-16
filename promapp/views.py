import sys
import time

from PIL import Image
from django_tables2 import RequestConfig
from datetime import date as datething
import django_tables2 as tables
from django.views.generic import ListView
import django.utils.html
import googleapiclient.discovery
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpRequest, HttpResponseRedirect
from django.template import loader
from html import unescape
import json
from google.oauth2 import id_token
from google.auth.transport import requests
from urllib.parse import urlparse
from urllib.parse import parse_qs
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from mailjet_rest import Client
import random
import string
from promapp.models import EmailData
from promapp.models import ApprovalEmailData
from promapp.models import Student

import io
from PIL import Image
import requests
from io import BytesIO
import base64
import pyheif

# from forms import StudentForm
# checking the server rn! checking the server rn! yeah lol
# AH, found it
# Seems like it works
# Do you see the shared terminal?


# Create your views here.
from promapp.forms import StudentForm
from promapp.forms import DateCreationForm
from promapp.forms import DateApprovalForm
from promapp.forms import UpdateStudentForm

wisd_aps = ["cynthia.patel@apps.wylieisd.net"]


def do_thing(request: HttpRequest):
    template = loader.get_template('neat.html')
    jsoninfo = json.loads(str(request.body.decode("utf-8")))
    context = {"some_message": jsoninfo["test"]}
    context = set_default_context(request.session, context)
    return HttpResponse(template.render(context, request))


def run_del(request):
    if not is_admin(request):
        return HttpResponse("Access not allowed!")
    students = Student.objects.all()
    email_datas = EmailData.objects.all()
    num = 0
    for student in students:
        for date in students:
            if student.dateEmail == date.email:
                for email_data in email_datas:
                    if student.email == email_data.wisd_date:
                        email_data.delete()
                        num = num + 1;
        for email_data in email_datas:
            if student.email == email_data.email:
                email_data.delete()
                num = num + 1;
    return HttpResponse("DELETED " + str(num) + " datas!")


def login_timedout(request):
    logged_in(request)  # updates the request
    if request.session["logged-in"]:  # checks if the user is logged in
        if time.time() >= request.session[
            "login-expire"]:  # if the time is exceeded then send true therefore loggin the user out

            return True
        else:  # don't send true and don't auto log them out
            return False


def logged_in(request):  # checks if the user is logged in
    if not ("logged-in" in request.session):
        request.session["logged-in"] = False
    return request.session["logged-in"]


def is_wisd(request):  # checks if the email is wylie isd
    logged_in(request)
    if "email" in request.session:
        return "wylieisd.net" in request.session["email"].split("@")[
            1]  # checks if the email ends with wylie in the end
    else:
        return False  # return false


admins = ["cynthia.patel@apps.wylieisd.net",
          "forsam860@apps.wylieisd.net",
          "jacquie.hiddink@apps.wylieisd.net",
          "meggan.narvaez@apps.wylieisd.net",
          "barbara.radford@apps.wylieisd.net",
          "susan.fajardo@apps.wylieisd.net",
          "michelle.rodges@apps.wylieisd.net",
          "robert.gawedzinski@apps.wylieisd.net",
          "michael.mason@apps.wylieisd.net",
          "jamie.busby@apps.wylieisd.net",
          "leny.philipose@apps.wylieisd.net",
          "michelle.bellamy@apps.wylieisd.net",
          "jonathan.campoverde@apps.wylieisd.net"]


def is_admin(request):  # checks if the user has admin access from the list of admins(teachers and devs)
    logged_in(request)
    if "email" in request.session:
        return request.session["email"] in admins or request.session["email"] in wisd_aps
    else:
        return False


def is_admin_email(email):
    return email in admins


def clear_session(request):
    request.session["logged-in"] = False


#     if not request.session is None:
#         for key in request.session:
#             request.session[key] = None


def login(request: HttpRequest, callback="/"):
    check_defaults(request)
    try:
        # Use the client_secret.json file to identify the application requesting
        # authorization. The client ID (from that file) and access scopes are required.
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=['https://www.googleapis.com/auth/userinfo.email', 'openid',
                    'https://www.googleapis.com/auth/userinfo.profile'],
        )
        # Indicate where the API server will redirect the user after the user completes
        # the authorization flow. The redirect URI is required. The value must exactly
        # match one of the authorized redirect URIs for the OAuth 2.0 client, which you
        # configured in the API Console. If this value doesn't match an authorized URI,
        # you will get a 'redirect_uri_mismatch' error.
        flow.redirect_uri = 'https://prom.ahmoit.net/oauth2callback'

        # Generate URL for request to Google's OAuth 2.0 server.
        # Use kwargs to set optional request parameters.
        authorization_url, state = flow.authorization_url(
            # Enable offline access so that you can refresh an access token without
            # re-prompting the user for permission. Recommended for web server apps.
            access_type='offline',
            # Enable incremental authorization. Recommended as a best practice.
            include_granted_scopes='false',
            prompt='select_account',
            state=callback
        )
        request.session['state'] = state
        print(authorization_url)
        return redirect(authorization_url)
    except ValueError:
        # Invalid token
        return HttpResponse("INVALID TOKEN")


def oauth2callback(request: HttpRequest):
    state = request.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "client_secret.json", scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email',
                                      'https://www.googleapis.com/auth/userinfo.profile'], state=state)

    flow.redirect_uri = "https://prom.ahmoit.net/oauth2callback"

    authorization_response = "https://prom.ahmoit.net" + request.get_full_path()
    request.session["authorization_response"] = authorization_response
    print(authorization_response)
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    request.session['credentials'] = credentials_to_dict(credentials)

    params = parse_qs(request.get_full_path(False).split("?")[1])
    if not ('error' in params):
        credentials_dict = request.session['credentials']
        creds = google.oauth2.credentials.Credentials(
            credentials_dict["token"],
            refresh_token=credentials_dict["refresh_token"],
            token_uri=credentials_dict["token_uri"],
            client_id=credentials_dict["client_id"],
            client_secret=credentials_dict["client_secret"],
            scopes=credentials_dict["scopes"])
        o = build('oauth2', 'v2', credentials=creds)
        uinfo = o.userinfo().get().execute()
        print(uinfo)
        if ("wylieisd.net" in str(uinfo["email"]).split("@")[1]) or True:
            request.session['logged-in'] = True
            request.session["login-expire"] = time.time() + 30 * 60  # (30 minutes before expire)
            request.session['email'] = uinfo["email"]
            request.session["first"] = uinfo["given_name"]
            if "family_name" in uinfo:
                request.session["last"] = uinfo["family_name"]
            else:
                request.session["last"] = ""
            response = requests.get(uinfo["picture"])
            request.session["picture"] = base64.b64encode(BytesIO(response.content).getvalue()).decode("utf-8")
        return redirect(params["state"][0].replace("_S_", "/"))
    return redirect('/')


def images(request: HttpRequest, image):
    print(image)
    f = open("templates/images/" + image, "rb")
    return HttpResponse(f.read())


def styles(request: HttpRequest, style):
    print(style)
    f = open("templates/styles/" + style, "rb")
    return HttpResponse(f.read(), content_type='text/css')


def scripts(request: HttpRequest, script):
    print(script)
    f = open("templates/scripts/" + script, "rb")
    return HttpResponse(f.read(), content_type='text/javascript')


def navbar(request: HttpRequest):
    check_defaults(request)
    template = loader.get_template('navbar.html')
    context = {}
    context = set_default_context(request.session, context)
    return HttpResponse(template.render(context, request), content_type='text/html')


def footer(request: HttpRequest):
    check_defaults(request)
    template = loader.get_template('footer.html')
    context = {}
    context = set_default_context(request.session, context)
    return HttpResponse(template.render(context, request), content_type='text/html')


def index(request):
    if login_timedout(request):
        clear_session(request)
        request.session["logged-in"] = False
        return HttpResponseRedirect("/login/_S_/")
    if datething.today() <= datething(2023,4,2):
        '''template = loader.get_template('buzzoff.html')
        context = {}
        context = set_default_context(request.session, context)
        return HttpResponseRedirect(template.render(context, request))'''
        return redirect('comebacklater/', permanent=True)
    check_defaults(request)
    template = loader.get_template('index.html')
    context = {}
    context = set_default_context(request.session, context)
    return HttpResponse(template.render(context, request))

def comebacklater(request):
    template = loader.get_template('comebacklater.html')
    context = {}
    context = set_default_context(request.session, context)
    return HttpResponse(template.render(context, request))


def logout(request):  # logs out the user, and loads the logout template
    request.session['logged-in'] = False
    template = loader.get_template('logout.html')  # gets the template from the right html file
    return HttpResponse(template.render({}, request))  # redirects the page


def get_ticket_view(request):
    if not logged_in(request):
        return redirect("/login/_S_createticket/")
    else:
        if login_timedout(request):
            clear_session(request)
            request.session["logged-in"] = False
            return HttpResponseRedirect("/login/_S_createticket/")
        if request.session["picture"] is None:
            return HttpResponseRedirect("/login/_S_createticket/")
    if not is_wisd(request):
        return redirect("/wisdonly/")
    students = Student.objects.all()
    student_exists = False
    for student in students:
        if student.email == request.session["email"]:
            student_exists = True
            break
    if student_exists:
        return redirect("/ticketexists")
    if request.method == 'POST':
        form = StudentForm(request.POST)
        if form.is_valid():
            date_email = {"email": form.data.get("date_email"), "wisd_date": request.session["email"]}
            # if not (form.data.get("date_email") == "none@none.com"):
            #     date_email = {"email": form.data.get("date_email"), "name": "Some Person's Date"}
            #
            #     date_email_keydata = {"email": form.data.get("date_email"), "wisd_date": request.session["email"]}
            #     key = generate_random_key_and_add(date_email_keydata)
            #     send(date_email,"Welcome to WISD Prom!", "You have be invited to PROM!!!!", "<h1>You have be invited to PROM!!!!</h1><br><br><a href=\"https://prom.ahmoit.net/date/"+date_email["email"]+"/"+key+"/\">https://prom.ahmoit.net/date/"+date_email["email"]+"/"+key+"/</a>")
            if request.session["picture"] is None:
                return HttpResponseRedirect("/login/_S_createticket/")
            bytes_thing = base64.b64decode(request.session["picture"].encode("utf-8"))
            print(bytes_thing)
            img = Image.open(BytesIO(bytes_thing))
            img.save("user_pictures/" + request.session["email"] + ".png", "png")
            request.session["picture"] = None
            student = Student.objects.create(
                first_name=request.session["first"],
                last_name=request.session["last"],
                email=request.session["email"],
                shirtSize=form.data.get("shirt_size"),
                dateEmail=date_email["email"],
                picture="user_pictures/" + request.session["email"] + ".png",
                isWisd=True,
                paid=False,
                ap_approved=True,
                wisd_approved=False,
                minor=True,
                public_school=True,
                received_ticket=False,
                ticket_num="",
                checked_in=False,
                received_shirt=False
            )
            student.save()

            template = ""
            with open('/var/www/html/templates/emails/requestsuccessful.html', "r") as f:
                for e in f:
                    template = template + str(e) + "\n"

            name = request.session["first"] + " " + request.session["last"]

            # templateHTML = template.replace("%student_name%", name).replace("%link%","https://www.google.com/")
            # templateNONHTML = template.replace("%student_name%", name).replace("%link%","https://www.google.com/")

            to_info = {"email": request.session["email"], "name": name}
            send(to_info, "Thank you for requesting a prom ticket!", template, template)
            print("AAAAAAAAAAA" + template)

            template = ""
            with open('/var/www/html/templates/emails/wisdapprovalneeded.html') as f:
                for e in f:
                    template = template + str(e) + "\n"
            template = template.replace("%link%", "https://prom.ahmoit.net/student/" + request.session["email"] + "/")
            for ap in wisd_aps:
                to_info = {"email": ap, "name": "WISD AP"}
            send(to_info, "Student needs approval!", template, template)

            context = {}
            context = set_default_context(request.session, context)
            return render(request, "ticketsuccess.html", context)
    else:
        form = StudentForm(initial={"date_email": "none@none.com"})
        context = {'form': form}
        context = set_default_context(request.session, context)
        return render(request, 'createticket.html', context)


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


def check_defaults(request):
    if not ("login-expire" in request.session):
        request.session["login-expire"] = time.time()
    if not ('logged-in' in request.session):
        request.session['logged-in'] = False
    if not ('consent' in request.session):
        request.session['consent'] = False
    if request.session["logged-in"]:
        if request.session["login-expire"] >= time.time():
            request.session["logged-in "] = False


def show_mysql_data(request):  # just styling the sql database to display the data
    str = ""
    for e in EmailData.objects.all():
        str = str + "\nEmail: " + e.email + " | Wisd_Date: " + e.wisd_date + " | Key: " + e.key
    return HttpResponse(str, request)


# FUNCTIONS TO SEND EMAIL:


def send(to, subject, message, messagehtml):  # to = (name, email) #style this email still in progress
    mailjet = Client(auth=('505731f6381478512f91dc2594e35f17', '286a704be18028fdcd3a743840cb0d28'), version='v3.1')
    # splitting up the email into parts
    data = {
        'Messages': [
            {
                "From": {
                    "Email": "no-reply@eclipsecraft.net",
                    "Name": "AHMOIT"
                },
                "To": [{
                    "Email": to["email"],
                    "Name": to["name"]
                }],
                "Subject": subject,
                "TextPart": message,
                "HTMLPart": (messagehtml)
            }
        ]
    }
    result = mailjet.send.create(data=data)
    print(result.status_code)
    print(result.json())


#     mailjet = Client()
# stuff to be stored in the database
# email -> generate key
def generate_random_key_and_add(given):  # generates a random key that will be the end of the url
    print("GENERATING KEY")
    key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in
                  range(50))
    print(key)
    student = EmailData.objects.create(email=given["email"], wisd_date=given["wisd_date"], key=key)
    student.save()
    return key  # 50 character random key generated


def set_default_context(session, context):  # default parameters
    if not "logged-in" in session:
        session["logged-in"] = False
    context["logged_in"] = session["logged-in"]
    context["email"] = "none"
    context["per_page"] = 10
    if session["logged-in"]:
        if "email" in session:
            context["email"] = session["email"]
            context["is_admin"] = is_admin_email(session["email"])  # checks if the user gets to access database
    return context


def wisd_only(request):
    context = {}
    context = set_default_context(request.session, context)
    return render(request, "wisdonly.html", context)


def ticket_exists(request):
    context = {}
    context = set_default_context(request.session, context)
    return render(request, "ticketexists.html", context)


def ticket_success(request):  # opens the ticket success html file and updates the the default
    context = {}
    context = set_default_context(request.session, context)
    return render(request, "ticketsuccess.html", context)


def print_location(request):
    print("---------------- START LOG -----------------")
    try:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        print("URL: "+str(request.get_full_path()))
        print("IP ADDR: "+str(x_forwarded_for))
        total = ""
        for key in request.session.keys():
            total=total+str(key)+" | "+str(request.session[key])+"\n"
        print("Session Data: " + total)
    except Exception:
        type, value, traceback = sys.exc_info()
        print("LOg error: "+str(type))
    print("---------------- END LOG -----------------")


def admin_only(request):  # opens the database html file and updates the the default
    context = {}
    context = set_default_context(request.session, context)
    print_location(request)
    return render(request, "adminonly.html", context)


def success(request):  # opens the success html file and updates the the default
    context = {}
    context = set_default_context(request.session, context)
    return render(request, "success.html", context)


def check_admin(email):
    admins = wisd_aps
    # print("EMAIL OUT:" + email)
    if email in admins:  # check if the user is an ademin
        return True
    else:
        return False


def check_allowed(email):
    allowed_emails = []
    if not ("wylieisd.net" in email.split("@") or "apps.wylieisd.net" in email.split("@")):
        if not email in allowed_emails:
            return False
    return True


def date_creation(request, email, key):
    print_location(request)
    if request.method == 'GET':
        data_objects = EmailData.objects.all()
        for object in data_objects:
            if object.email == email and object.key == key:
                students = Student.objects.all()
                for student in students:
                    if student.email == email:
                        return HttpResponseRedirect("/ticketexists/")
                date_exists = False
                for student in students:
                    if student.dateEmail == email:
                        date_exists = True
                if not date_exists:
                    return HttpResponseRedirect("/invalid_date/")
                request.session["DateCreation"] = True
                #                 request.session["email"] = email
                request.session["wisd_date"] = email
                request.session["key"] = key
                form = DateCreationForm()
                context = {"form": form}
                return HttpResponse(render(request, "datecreation.html", context))
    elif request.method == 'POST':
        if not (request.session["DateCreation"] == True
                and request.session["wisd_date"] == email
                and request.session["key"] == key):
            return HttpResponseRedirect("/invalidsession/")
        students = Student.objects.all()
        # Continue
        form = DateCreationForm(request.POST, request.FILES)
        if form.is_valid():

            first_name = ""
            last_name = ""
            email1 = ""
            shirtSize = ""
            date_email = ""
            picture = None
            minor = False
            public_school = False
            isWisd = False
            paid = False
            ap_approved = False
            wisd_approved = False

            first_name = form.data.get("first_name")
            last_name = form.data.get("last_name")
            email1 = form.data.get("email")
            shirtSize = form.data.get("shirt_size")
            for student in students:
                if student.dateEmail == email:
                    date_email = student.email
            picture = request.FILES['picture']
            not_minor = form.data.get("not_minor")
            if not_minor is None:
                not_minor = False
            else:
                not_minor = True
            minor = not not_minor
            public_school = form.data.get("public_school")
            if public_school is None:
                public_school = False
            else:
                public_school = True
            # Already know is not wisd
            # Alread know is not paid
            # etc

            for student in students:
                if student.email == email:
                    return HttpResponseRedirect("/ticketexists/")

            student = Student.objects.create(
                first_name=first_name,
                last_name=last_name,
                email=email1,
                shirtSize=shirtSize,
                dateEmail=date_email,
                picture=picture,
                isWisd=isWisd,
                paid=paid,
                ap_approved=ap_approved,
                wisd_approved=wisd_approved,
                minor=minor,
                public_school=public_school,
                received_ticket=False,
                ticket_num="",
                checked_in=False,
                received_shirt=False

            )
            #             print("DADADADADADADADAD")
            #             print(public_school)
            # #             print(form.data.get("public_school"))
            #             print(minor)
            if public_school or (not public_school and minor):
                email_key = ''.join(
                    random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _
                    in range(50))
                email_data = ApprovalEmailData.objects.create(
                    date_email=email1,
                    ap_email=form.data.get("permission_email"),
                    key=email_key
                )
                wisd_student = None
                for student in Student.objects.all():
                    if student.dateEmail == email:
                        wisd_student = student
                student.save()
                data_objects = EmailData.objects.all()
                for object in data_objects:
                    if object.email == email and object.key == key:
                        object.delete()
                        a = ""
                email_data.save()

                date_name = first_name + " " + last_name

                template = ""
                with open('/var/www/html/templates/emails/dateapapprovalneeded.html') as f:
                    for e in f:
                        template = template + str(e) + "\n"
                template = template.replace("%date_name%", date_name).replace("%wisd_name%",
                                                                              wisd_student.first_name + " " + wisd_student.last_name).replace(
                    "%link%",
                    "https://prom.ahmoit.net/dateapprove/" + form.data.get("permission_email") + "/" + email_key + "/")
                send({"email": form.data.get("permission_email"), "name": date_name + "'s School AP"},
                     "Information Updated", template, template)

                template = ""
                with open('/var/www/html/templates/emails/requestsuccessful.html') as f:
                    for e in f:
                        template = template + str(e) + "\n"

                to_info = {"email": email1, "name": date_name}
                send(to_info, "Thank you for requesting a prom ticket!", template, template)
            else:
                student.ap_approved = True
                student.save()
                data_objects = EmailData.objects.all()
                for object in data_objects:
                    if object.email == email and object.key == key:
                        a = ""
                        object.delete()
                date_name = first_name + " " + last_name
                template = ""
                with open('/var/www/html/templates/emails/requestsuccessful.html') as f:
                    for e in f:
                        template = template + str(e) + "\n"

                to_info = {"email": email1, "name": date_name}
                send(to_info, "Thank you for requesting a prom ticket!", template, template)

                template = ""

                with open('/var/www/html/templates/emails/wisdapprovalneeded.html') as f:
                    for e in f:
                        template = template + str(e) + "\n"
                template = template.replace("%link%", "https://prom.ahmoit.net/student/" + student.email + "/")
                for ap in wisd_aps:
                    to_info = {"email": ap, "name": "WISD AP"}
                    send(to_info, "Student needs approval!", template, template)
            return HttpResponseRedirect("/ticketsuccess/")
        else:
            response = "Error: "
            for error in form.errors:
                response = response + "\n" + error
            return HttpResponse(response, request)


def date_approve(request, email, key):
    if request.method == 'GET':
        data_objects = ApprovalEmailData.objects.all()
        for object in data_objects:
            if object.ap_email == email and object.key == key:
                wisd_student = None
                date_student = None
                students = Student.objects.all()
                for student in students:
                    if student.email == object.date_email:
                        date_student = student
                    if student.dateEmail == object.date_email:
                        wisd_student = student
                form = DateApprovalForm()
                context = {"form": form, "wisd_student": wisd_student, "date_student": date_student}
                # with open(wisd_student.picture.path, "rb") as image:
                #     data_base64 = base64.b64encode(image.read())  # encode to base64 (bytes)
                #     data_base64 = data_base64.decode()
                #     print(data_base64)
                context["wisd_image"] = get_image_data(wisd_student.picture.path)
                # with open(date_student.picture.path, "rb") as image:
                #     data_base64 = base64.b64encode(image.read())  # encode to base64 (bytes)
                #     data_base64 = data_base64.decode()
                #     print(data_base64)
                context["date_image"] = get_image_data(date_student.picture.path)
                context = set_default_context(request.session, context)
                return HttpResponse(render(request, "dateapproval.html", context))
    elif request.method == 'POST':
        data_objects = ApprovalEmailData.objects.all()
        for object in data_objects:
            if object.ap_email == email and object.key == key:
                date_student = None
                students = Student.objects.all()
                for student in students:
                    if student.email == object.date_email:
                        date_student = student
                form = DateApprovalForm(request.POST)
                approved = False
                if "approve" in form.data:  # updates the approved variable after checking form
                    approved = True
                # feeds the info into variables..
                date_student.ap_email = email
                date_student.ap_approved = approved
                date_student.save()

                date_name = date_student.first_name + " " + date_student.last_name

                if approved:
                    template = ""
                    with open('/var/www/html/templates/emails/dateapapproved.html') as f:
                        for e in f:
                            template = template + str(e) + "\n"
                    send({"name": student.first_name + " " + student.last_name, "email": student.email},
                         "Information Updated", template, template)

                    template = ""

                    with open('/var/www/html/templates/emails/wisdapprovalneeded.html') as f:
                        for e in f:
                            template = template + str(e) + "\n"
                    template = template.replace("%link%", "https://prom.ahmoit.net/student/" + date_student.email + "/")
                    for ap in wisd_aps:
                        to_info = {"email": ap, "name": "WISD AP"}
                        send(to_info, "Student needs approval!", template, template)
                else:
                    template = ""
                    with open('/var/www/html/templates/emails/denied.html') as f:
                        for e in f:
                            template = template + str(e) + "\n"
                    send({"name": student.first_name + " " + student.last_name, "email": student.email},
                         "Information Updated", template, template)

                return HttpResponseRedirect("/success/")


def get_image_data(path):
    output = io.BytesIO()
    if "heic" in path.lower():
        with open(path, "rb") as fi:
            try:
                im = pyheif.read_heif(fi.read())

                # Convert to other file format like jpeg
                img = Image.frombytes(im.mode, im.size, im.data, "raw", im.mode, im.stride)
                img.save(path, format='JPEG')
                img.save(output, format="jpeg")
            except Exception:
                try:
                    img = Image.open(path)
                    img = img.convert("RGB")
                    img.thumbnail((512, 512), Image.ANTIALIAS)
                    img.save(path, format='JPEG')
                    img.save(output, format='JPEG')
                except Exception:
                    a = ""
    else:
        img = Image.open(path)
        img = img.convert("RGB")
        img.thumbnail((512, 512), Image.ANTIALIAS)
        img.save(path, format='JPEG')
        img.save(output, format='JPEG')
    return base64.b64encode(output.getvalue()).decode()


def student_view(request, student):
    print_location(request)
    if not logged_in(request):
        return redirect("/login/" + request.get_full_path().replace("/", "_S_") + "/")
    if not is_admin(request):
        # check to make sure user is a admin
        return redirect("/adminonly/")
    if request.method == "GET":
        student = Student.objects.get(email=student)
        # shows all the info pulled form the student data
        form = UpdateStudentForm(initial={
            'shirt_size': student.shirtSize,
            'first_name': student.first_name,
            'last_name': student.last_name,
            'date_email': student.dateEmail,
            'ap_approved': student.ap_approved,
            'ap_email': student.ap_email,
            'wisd_approved': student.wisd_approved,
            'received_ticket': student.received_ticket,
            'received_shirt': student.received_shirt,
            'ticket_num': student.ticket_num,
            'paid': student.paid
        })
        date = None
        context = {"form": form, "student": student, "date": date}
        if not (student.dateEmail == ""):
            try:
                date = Student.objects.get(email=student.dateEmail)
                # with open(date.picture.path, "rb") as image:
                #
                #     data_base64 = base64.b64encode(image.read())  # encode to base64 (bytes)
                #     data_base64 = data_base64.decode()
                #     #                     print(data_base64)
                #     context["date_picture"] = data_base64
                # data_base64 = base64.b64encode(get_image_bytes(date.picture.path)).decode()
                context["date_picture"] = get_image_data(date.picture.path)
                context["date"] = date
            except Exception as e:  # any errors shown
                print("oof: " + str(e))
        # with open(student.picture.path, "rb") as image:
        #     data_base64 = base64.b64encode(image.read())  # encode to base64 (bytes)
        #     data_base64 = data_base64.decode()
        #     #                     print(data_base64)
        context["student_picture"] = get_image_data(student.picture.path)
        context = set_default_context(request.session, context)
        return HttpResponse(render(request, "studentview.html", context))
    elif request.method == "POST":
        form = UpdateStudentForm(request.POST)
        if form.is_valid():
            student = Student.objects.get(email=student)

            previousWISDApproval = student.wisd_approved
            previousPaid = student.paid

            student.first_name = form.data.get("first_name")
            student.last_name = form.data.get("last_name")
            student.shirtSize = form.data.get("shirt_size")
            '''
            updates a bunch of variables given the form data BELOW
            '''
            if "ap_approved" in form.data:
                student.ap_approved = True
            else:
                student.ap_approved = False
            if "wisd_approved" in form.data:
                student.wisd_approved = True
            else:
                student.wisd_approved = False
            if "received_ticket" in form.data:
                student.received_ticket = True
            else:
                student.received_ticket = False
            if "received_shirt" in form.data:
                student.received_shirt = True
            else:
                student.received_shirt = False
            if "paid" in form.data:
                student.paid = True
            else:
                student.paid = False
            if "ticket_num" in form.data:
                student.ticket_num = form.data.get("ticket_num")

            previousDateEmail = student.dateEmail

            if "date_email" in form.data:
                student.dateEmail = form.data.get("date_email")

            if "picture" in request.FILES:
                student.picture = request.FILES["picture"]

            previous_ap_email = student.ap_email

            if "ap_email" in form.data and form.data.get("ap_email") != "":
                student.ap_email = form.data.get("ap_email")

            if student.isWisd and previous_ap_email != student.ap_email:
                if student.public_school or (not student.public_school and student.minor):
                    email_key = ''.join(
                        random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase)
                        for _ in range(50))
                    email_data = ApprovalEmailData.objects.create(
                        date_email=student.email,
                        ap_email=student.ap_email,
                        key=email_key
                    )
                    wisd_student = None
                    for alt_student in Student.objects.all():
                        if student.dateEmail == student.email:
                            wisd_student = alt_student

                    class PlaceholderStudent:
                        def __init__(self, first_name, last_name):
                            self.first_name = first_name
                            self.last_name = last_name

                    if wisd_student is None:
                        wisd_student = PlaceholderStudent("john", "doe")
                    email_data.save()

                    date_name = student.first_name + " " + student.last_name

                    template = ""
                    with open('/var/www/html/templates/emails/dateapapprovalneeded.html') as f:
                        for e in f:
                            template = template + str(e) + "\n"
                    template = template.replace("%date_name%", date_name).replace("%wisd_name%",
                                                                                  wisd_student.first_name + " " + wisd_student.last_name).replace(
                        "%link%", "https://prom.ahmoit.net/dateapprove/" + student.ap_email + "/" + email_key + "/")
                    send({"email": student.ap_email, "name": date_name + "'s School AP"},
                         "Approval Needed", template, template)

            if previousDateEmail != student.dateEmail:
                if student.wisd_approved:
                    if not (student.dateEmail == "none@none.com"):
                        date_email = {"email": student.dateEmail,
                                      "name": student.first_name + " " + student.last_name + "'s Date"}

                        date_email_keydata = {"email": student.dateEmail, "wisd_date": student.email}
                        key = generate_random_key_and_add(date_email_keydata)

                        template = ""
                        with open('/var/www/html/templates/emails/dateinvitation.html') as f:
                            for e in f:
                                template = template + str(e) + "\n"

                        template = template.replace("%accept_link%", "https://prom.ahmoit.net/date/" + date_email[
                            "email"] + "/" + key + "/").replace("%name%", student.first_name + " " + student.last_name)
                        send(date_email, "Welcome to WISD Prom!", template, template)
                        # "<h1>You have be invited to PROM!!!!</h1><br><br><a href=\"https://prom.ahmoit.net/date/"+date_email["email"]+"/"+key+"/\">https://prom.ahmoit.net/date/"+date_email["email"]+"/"+key+"/</a>")

            template = ""
            if previousWISDApproval == False and student.wisd_approved == True:

                with open('/var/www/html/templates/emails/wisdapproved.html') as f:
                    for e in f:
                        template = template + str(e) + "\n"
                payment_link = "https://wylie-isd.revtrak.net/high-schools-8/wylie-hs-group/#/v/wylie-hs-2022-prom"
                today = datething.today()
                if today.month == 5:
                    if today.day > 8:
                        payment_link = "https://wylie-isd.revtrak.net/high-schools-8/wylie-hs-group/#/v/Wylie-HS-2022-Prom-170"
                    if today.day > 13:
                        payment_link = "https://wylie-isd.revtrak.net/high-schools-8/wylie-hs-group/#/v/Wylie-HS-2022-Prom-171"
                template = template.replace("%payment_link%", payment_link)
                send({"name": student.first_name + " " + student.last_name, "email": student.email},
                     "Information Updated",
                     template, template)
            if (student.isWisd):
                if previousWISDApproval == False and student.wisd_approved == True:

                    if not (student.dateEmail == "none@none.com"):
                        date_email = {"email": student.dateEmail,
                                      "name": student.first_name + " " + student.last_name + "'s Date"}

                        date_email_keydata = {"email": student.dateEmail, "wisd_date": student.email}
                        key = generate_random_key_and_add(date_email_keydata)

                        template = ""
                        with open('/var/www/html/templates/emails/dateinvitation.html') as f:
                            for e in f:
                                template = template + str(e) + "\n"

                        template = template.replace("%accept_link%", "https://prom.ahmoit.net/date/" + date_email[
                            "email"] + "/" + key + "/").replace("%name%", student.first_name + " " + student.last_name)
                        send(date_email, "Welcome to WISD Prom!", template, template)
                        # "<h1>You have be invited to PROM!!!!</h1><br><br><a href=\"https://prom.ahmoit.net/date/"+date_email["email"]+"/"+key+"/\">https://prom.ahmoit.net/date/"+date_email["email"]+"/"+key+"/</a>")

            if previousPaid == False and student.paid == True:
                template = ""
                with open('/var/www/html/templates/emails/paidsuccess.html') as f:
                    for e in f:
                        template = template + str(e) + "\n"
                send({"name": student.first_name + " " + student.last_name, "email": student.email},
                     "Information Updated", template, template)
            student.save()
        # #              models.CharField(max_length=30, null=True)
        # #     last_name = models.CharField(max_length=30, null=True)
        # #     email = models.EmailField(unique=True)
        # #     shirtSize = models.CharField(max_length=4, choices=SHIRT_SIZES)
        # #     dateEmail = models.EmailField(null=True,unique=True)
        # #     picture = models.ImageField(null=True, upload_to="user_pictures/")
        # #     minor = models.BooleanField()
        # #     public_school = models.BooleanField()
        # #     isWisd = models.BooleanField()
        # #     paid = models.BooleanField()
        # #     ap_approved = models.BooleanField()
        # #     ap_email = models.EmailField()
        # #     wisd_approved = models.BooleanField()
        # #     received_ticket = models.BooleanField()
        # #     ticket_num = models.CharField(
        #             templateHTML = """
        #                 <p>Hello %name%, your information relating to WHS prom has been updated!</p>
        #                 <br>
        #                 <p>If you are now both Wylie Approved and AP Approved and you have not yet paid, please pay at: <a href="%payment_link%">%payment_link%</a>!</p>
        #                 <br>
        #                 <p>First Name: %first%</p><br>
        #                 <p>Last Name: %last%</p><br>
        #                 <p>Email: %email%</p><br>
        #                 <p>Shirt Size: %shirt_size%</p><br>
        #                 <p>Date Email: %date_email%</p><br>
        #                 <p>Has Paid: %paid%</p><br>
        #                 <p>AP Approved: %ap_approved%</p><br>
        #                 <p>Wylie Approved: %wylie_approved%</p><br>
        #                 <p>Received Ticket: %received_ticket%</p><br>
        #                 <p>Ticket Number: %ticket_num%</p>
        #             """
        #
        #             templateNONHTML = """
        #                 Hello %name%, your information relating to WHS prom has been updated!
        #
        #                 If you are now both Wylie Approved and AP Approved and you have not yet paid, please pay at: %payment_link%!
        #
        #                 First Name: %first%
        #                 Last Name: %last%
        #                 Email: %email%
        #                 Shirt Size: %shirt_size%
        #                 Date Email: %date_email%
        #                 Has Paid: %paid%
        #                 AP Approved: %ap_approved%
        #                 Wylie Approved: %wylie_approved%
        #                 Received Ticket: %received_ticket%
        #                 Ticket Number: %ticket_num%
        #             """
        #
        #             name = student.first_name+" "+student.last_name
        #             templateHTML = templateHTML.replace("%payment_link%","www.google.com").replace("%name%",name).replace("%first%",student.first_name).replace("%last%",student.last_name).replace("%email%",student.email).replace("%shirt_size%",student.shirtSize).replace("%date_email%",student.dateEmail).replace("%paid%",str(student.paid)).replace("%ap_approved%",str(student.ap_approved)).replace("%wylie_approved%",str(student.wisd_approved)).replace("%received_ticket%",str(student.received_ticket)).replace("%ticket_num%",student.ticket_num)
        #             templateNONHTML = templateNONHTML.replace("%payment_link%","www.google.com").replace("%name%",name).replace("%first%",student.first_name).replace("%last%",student.last_name).replace("%email%",student.email).replace("%shirt_size%",student.shirtSize).replace("%date_email%",student.dateEmail).replace("%paid%",str(student.paid)).replace("%ap_approved%",str(student.ap_approved)).replace("%wylie_approved%",str(student.wisd_approved)).replace("%received_ticket%",str(student.received_ticket)).replace("%ticket_num%",student.ticket_num)
        #
        #             if student.ap_approved and not student.wisd_approved:#send the right email given the circumstance upon any change
        #                 send({"name":name,"email":student.email},"Information Updated",templateNONHTML,templateHTML)
        #
        #             if (student.paid and student.ap_approved and student.wisd_approved) or (not student.minor and student.paid):
        #                 templateHTML = """
        #                     <p>Hello %name%, your information relating to WHS prom has been updated!</p>
        #                     <br>
        #                     <p>You are approved to receive your ticket, you have successfully paid!</p>
        #                     <p>Has Paid: %paid%</p><br>
        #
        #                     <p>Instructions here to detail on how student should receive their ticket</p>
        #                 """
        #
        #                 templateNONHTML = """
        #                     Hello %name%, your information relating to WHS prom has been updated!
        #
        #                     You are approved to receive your ticket, you have successfully paid!
        #                     Has Paid: %paid%</p><br>
        #
        #                     Instructions here to detail on how student should receive their ticket
        #                 """
        #
        #                 name = student.first_name+" "+student.last_name
        #                 templateHTML = templateHTML.replace("%payment_link%","www.google.com").replace("%name%",name).replace("%first%",student.first_name).replace("%last%",student.last_name).replace("%email%",student.email).replace("%shirt_size%",student.shirtSize).replace("%date_email%",student.dateEmail).replace("%paid%",str(student.paid)).replace("%ap_approved%",str(student.ap_approved)).replace("%wylie_approved%",str(student.wisd_approved)).replace("%received_ticket%",str(student.received_ticket)).replace("%ticket_num%",student.ticket_num)
        #                 templateNONHTML = templateNONHTML.replace("%payment_link%","www.google.com").replace("%name%",name).replace("%first%",student.first_name).replace("%last%",student.last_name).replace("%email%",student.email).replace("%shirt_size%",student.shirtSize).replace("%date_email%",student.dateEmail).replace("%paid%",str(student.paid)).replace("%ap_approved%",str(student.ap_approved)).replace("%wylie_approved%",str(student.wisd_approved)).replace("%received_ticket%",str(student.received_ticket)).replace("%ticket_num%",student.ticket_num)
        #
        #                 send({"name":name,"email":student.email},"Information Updated: Paid",templateNONHTML,templateHTML)
        return HttpResponseRedirect("/student/" + student.email)


class StudentTable(tables.Table):  # gets the info from the table and stores the data in variables within the class
    student_image = tables.TemplateColumn(
        verbose_name="Image",
        template_code="<img src=\"data:image/jpeg;base64,{{record.student_image}}\" style=\"height:100%; max-width: 250px\">")
    name = tables.Column()
    email = tables.Column()
    shirt_size = tables.Column()
    paid = tables.Column()
    wylie_app = tables.TemplateColumn(
        verbose_name="Wylie Approved",
        template_code="<a href=\"/wylieapp/{{ record.email }}/{{ record.redirect_uri }}/\">{{record.wylie_approved}}</a>")
    ap_approved = tables.Column()
    ticket_number = tables.Column()
    got_shirt = tables.TemplateColumn(
        verbose_name="Received Shirt",
        template_code="<a href=\"/recshirt/{{ record.email }}/{{ record.redirect_uri }}/\">{{record.received_shirt}}</a>")
    checked_in = tables.TemplateColumn(
        verbose_name="Checked In",
        template_code="<a href=\"/checkin/{{ record.email }}/{{ record.redirect_uri }}/\">{{record.checkedin}}</a>")
    email_link = tables.TemplateColumn(
        verbose_name="Click To Edit",
        template_code="<a href=\"{{ record.edit_link }}\">Edit</a>")


def wylieapp(request, student_email, redirect_thing):
    if not logged_in(request):
        return redirect("/login/" + request.get_full_path().replace("/", "_S_") + "/")
    elif not is_admin(request):
        return redirect("/adminonly/")
    students = Student.objects.all()
    for student in students:
        if student.email == student_email:
            previousWISDApproval = student.wisd_approved
            if student.wisd_approved:
                student.wisd_approved = False
            else:
                student.wisd_approved = True
            student.save()
            template = ""
            if previousWISDApproval == False and student.wisd_approved == True:

                with open('/var/www/html/templates/emails/wisdapproved.html') as f:
                    for e in f:
                        template = template + str(e) + "\n"
                payment_link = "https://wylie-isd.revtrak.net/high-schools-8/wylie-hs-group/#/v/wylie-hs-2022-prom"
                today = datething.today()
                if today.month == 5:
                    if today.day > 8:
                        payment_link = "https://wylie-isd.revtrak.net/high-schools-8/wylie-hs-group/#/v/Wylie-HS-2022-Prom-170"
                    if today.day > 13:
                        payment_link = "https://wylie-isd.revtrak.net/high-schools-8/wylie-hs-group/#/v/Wylie-HS-2022-Prom-171"
                template = template.replace("%payment_link%", payment_link)
                send({"name": student.first_name + " " + student.last_name, "email": student.email},
                     "Information Updated",
                     template, template)
            if (student.isWisd):
                if previousWISDApproval == False and student.wisd_approved == True:

                    if not (student.dateEmail == "none@none.com"):
                        date_email = {"email": student.dateEmail,
                                      "name": student.first_name + " " + student.last_name + "'s Date"}

                        date_email_keydata = {"email": student.dateEmail, "wisd_date": student.email}
                        key = generate_random_key_and_add(date_email_keydata)

                        template = ""
                        with open('/var/www/html/templates/emails/dateinvitation.html') as f:
                            for e in f:
                                template = template + str(e) + "\n"

                        template = template.replace("%accept_link%", "https://prom.ahmoit.net/date/" + date_email[
                            "email"] + "/" + key + "/").replace("%name%", student.first_name + " " + student.last_name)
                        send(date_email, "Welcome to WISD Prom!", template, template)
                        # "<h1>You have be invited to PROM!!!!</h1><br><br><a href=\"https://prom.ahmoit.net/date/"+date_email["email"]+"/"+key+"/\">https://prom.ahmoit.net/date/"+date_email["email"]+"/"+key+"/</a>")
    return HttpResponse('<script type="text/javascript">window.location.href = "locc";</script>'.replace("locc",
                                                                                                         redirect_thing.replace(
                                                                                                             "_S_",
                                                                                                             "/")))


def recshirt(request, student_email, redirect_thing):
    if not logged_in(request):
        return redirect("/login/" + request.get_full_path().replace("/", "_S_") + "/")
    elif not is_admin(request):
        return redirect("/adminonly/")
    students = Student.objects.all()
    for student in students:
        if student.email == student_email:
            if student.received_shirt:
                student.received_shirt = False
            else:
                student.received_shirt = True
            student.save()
    return HttpResponse('<script type="text/javascript">window.location.href = "locc";</script>'.replace("locc",
                                                                                                         redirect_thing.replace(
                                                                                                             "_S_",
                                                                                                             "/")))


def checkin(request, student_email, redirect_thing):
    if not logged_in(request):
        return redirect("/login/" + request.get_full_path().replace("/", "_S_") + "/")
    elif not is_admin(request):
        return redirect("/adminonly/")
    students = Student.objects.all()
    for student in students:
        if student.email == student_email:
            if student.checked_in:
                student.checked_in = False
            else:
                student.checked_in = True
            student.save()
    return HttpResponse('<script type="text/javascript">window.location.href = "locc";</script>'.replace("locc",
                                                                                                         redirect_thing.replace(
                                                                                                             "_S_",
                                                                                                             "/")))


def deleteThing(request, student_email):
    print_location(request)
    if not logged_in(request):
        return redirect("/login/" + request.get_full_path().replace("/", "_S_") + "/")
    elif not is_admin(request):
        return redirect("/adminonly/")
    students = Student.objects.all()
    dateEmail = ""
    for student in students:
        if student.email == student_email:
            if student.dateEmail != "none@none.com":
                for datestudent in students:
                    # dateEmail = datestudent.email
                    if datestudent.dateEmail == student.email:
                        datestudent.dateEmail = "none@none.com"
                        datestudent.save()
            student.save()
            student.delete()
    if dateEmail == "":
        return HttpResponse('<script type="text/javascript">window.location.href = "/database/";</script>')
    else:
        return HttpResponse(
            '<script type="text/javascript">window.location.href = "/student/' + dateEmail + '/";</script>')
    # return HttpResponse('Hello!')


def database_lookup(request, var=None):  # database lookup
    print_location(request)
    if not logged_in(request):
        return redirect("/login/" + request.get_full_path().replace("/", "_S_") + "/")
    elif not is_admin(request):
        return redirect("/adminonly/")
    if request.method == "GET":
        students_for_table = []
        if var is None:
            students = Student.objects.all()
            print("Student Length: " + str(len(students)))
            for student in students:
                edit_link = "https://prom.ahmoit.net/student/" + student.email + "/"
                # with open(student.picture.path, "rb") as image:
                #     data_base64 = base64.b64encode(image.read())  # encode to base64 (bytes)
                #     data_base64 = data_base64.decode()
                students_for_table.insert(len(students_for_table), {
                    "student_image": get_image_data(student.picture.path),
                    "name": student.first_name + " " + student.last_name,
                    "email": student.email,
                    "shirt_size": student.shirtSize,
                    "ticket_number": student.ticket_num,
                    "edit_link": edit_link,
                    "paid": student.paid,
                    "wylie_approved": student.wisd_approved,
                    "ap_approved": student.ap_approved,
                    "checkedin": student.checked_in,
                    "received_shirt": student.received_shirt,
                    "redirect_uri": request.get_full_path().replace("/", "_S_")
                })
        else:
            students = Student.objects.all()
            for student in students:
                full_name = student.first_name + " " + student.last_name
                editlink = ""
                var = str(var)
                if var.lower() in student.email.lower() or var.lower() in student.first_name.lower() or var.lower() in student.last_name.lower() or var.lower() in full_name.lower() or var.lower() in student.dateEmail.lower() or var.lower() in student.ticket_num.lower():
                    edit_link = "https://prom.ahmoit.net/student/" + student.email + "/"
                    # with open(student.picture.path, "rb") as image:
                    #     data_base64 = base64.b64encode(image.read())  # encode to base64 (bytes)
                    #     data_base64 = data_base64.decode()
                    students_for_table.insert(len(students_for_table), {
                        "student_image": get_image_data(student.picture.path),
                        "name": student.first_name + " " + student.last_name,
                        "email": student.email,
                        "shirt_size": student.shirtSize,
                        "ticket_number": student.ticket_num,
                        "edit_link": edit_link,
                        "paid": student.paid,
                        "wylie_approved": student.wisd_approved,
                        "ap_approved": student.ap_approved,
                        "checkedin": student.checked_in,
                        "received_shirt": student.received_shirt,
                        "redirect_uri": request.get_full_path().replace("/", "_S_")
                    })
        table = StudentTable(students_for_table)
        table.paginate(page=request.GET.get("page", 1), per_page=10)
        RequestConfig(request, paginate={"per_page": 100}).configure(table)
        context = {"table": table}
        return HttpResponse(render(request, "database.html", context))
    elif request.method == "POST":
        if "var" in request.POST:
            if not request.POST["var"] == "":
                return redirect("/database/" + request.POST["var"] + "/")
        return redirect("/database")

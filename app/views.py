import numpy as np
import pandas as pd
import os
import matplotlib.pyplot as plt
import pickle
import json
import re
import hashlib
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from flask_login import login_required, current_user
from flask import Blueprint, render_template, jsonify, request, send_file, redirect, url_for
from app.functions import *
from .models import Query, User
from . import db

views = Blueprint("views", __name__)

@views.route("/", methods=["GET", "POST"])
def index():
    return redirect(url_for("auth.login"))

@views.route("/dashboard")
@login_required
def dashboard():
    total_0 = 0
    total_1 = 0

    try:
        for i in range(len(current_user.queries)):
            if "benign" == current_user.queries[i].label:
                total_0 += 1
            elif "malicious" == current_user.queries[i].label:
                total_1 += 1

        save_path = "app/static/reports/"

        label = np.array(["benign", "malicious"])
        values = np.array([total_0, total_1])
        colors = ["blue", "red"]

        plt.figure(figsize=(5, 5))
        plt.bar(label, values, color=colors)
        plt.title("Total Queries per Category")
        plt.savefig(save_path + "db_total.png")

        plt.figure(figsize=(5, 5))
        plt.pie(values, labels=label)
        plt.title("Total Queries per Category")
        plt.savefig(save_path + "db_total2.png")

    except:
        pass

    return render_template("dashboard.html", user=current_user)

@views.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded_file = request.files["file"]
        if uploaded_file.filename != "":
            file_path = os.path.join("app/static/uploads", uploaded_file.filename)
            uploaded_file.save(file_path)
            file_hash = hashlib.md5(open(file_path, "rb").read()).hexdigest()
            model = pickle.load(open("app/models/rf.pkl", "rb"))

            test_df = pd.DataFrame(columns=columns)
            test_df.loc[0, "filename"] = uploaded_file.filename

            a = APK(file_path)
            d = DalvikVMFormat(a.get_dex())

            permissions = a.get_permissions()
            manifest = a.get_android_manifest_xml()
            intent_filters = manifest.findall(".//intent-filter")

            found_permissions = []
            found_api_signatures = []
            found_intents = []
            found_keywords = []

            for permission in permissions:
                permissions = permission.split(".")[-1]
                if permission in permissions_list:
                    found_permissions.append(permission)

            for permission in permissions_list:
                if permission in found_permissions:
                    test_df[permission] = 1
                else:
                    test_df[permission] = 0

            for method in d.get_methods():
                for api_call in api_call_signatures:
                    if re.search(api_call, method.get_descriptor()):
                        found_api_signatures.append(api_call)

            for api_call in api_call_signatures:
                if api_call in found_api_signatures:
                    test_df[api_call] = 1
                else:
                    test_df[api_call] = 0

            for intent_filter in intent_filters:
                action_elements = intent_filter.findall(".//action")
                for action_element in action_elements:
                    action_value = action_element.get("{http://schemas.android.com/apk/res/android}name")
                    for intent in intents:
                        if re.search(intent, action_value):
                            found_intents.append(intent)

            for intent in intents:
                if intent in found_intents:
                    test_df[intent] = 1
                else:
                    test_df[intent] = 0

            for method in d.get_methods():
                for keyword in keywords:
                    try:
                        if re.search(keyword, method.get_code().get_instruction()):
                            found_keywords.append(keyword)

                    except:
                        pass

            for keyword in keywords:
                if keyword in found_keywords:
                    test_df[keyword] = 1
                else:
                    test_df[keyword] = 0

            dropped = test_df.drop("filename", axis=1)
            result = model.predict(dropped)
            for i in range(len(test_df)):
                test_df.loc[i, "label"] = "benign" if result[i] == 0 else "malware"
                query_text = test_df.loc[i, "filename"]
                label = test_df.loc[i, "label"]
                new_query = Query(query_text=query_text, label=label, user_id=current_user.id, file_hash=file_hash)
                db.session.add(new_query)
                db.session.commit()

            if not os.path.isdir(f"app/static/reports/{uploaded_file.filename[:-4]}"):
                os.makedirs(f"app/static/reports/{uploaded_file.filename[:-4]}")

            save_path = f"app/static/reports/{uploaded_file.filename[:-4]}/"
            test_df.to_csv(f"{save_path}{uploaded_file.filename[:-4]}_processed.csv")

            return render_template("statistics.html", user=current_user, selected=True, report=test_df, folder=f"{uploaded_file.filename[:-4]}", permissions_list=permissions_list, api_call_signatures=api_call_signatures, intents=intents, keywords=keywords)
        
    return render_template("upload.html", user=current_user)
        
@views.route("/delete-query", methods=["POST"])
def delete_query():
    qu = json.loads(request.data)
    queryId = qu["id"]
    qu = Query.query.get(queryId)
    if qu:
        if qu.user_id == current_user.id:
            db.session.delete(qu)
            db.session.commit()

    return jsonify({})

@views.route("/download_csv/<filename>", methods=["GET"])
@login_required
def download_csv(filename):
    folder_path = os.path.join("static/reports", filename[:-4])
    csv_file_path = os.path.join(folder_path, f"{filename[:-4]}_processed.csv")
    return send_file(csv_file_path, as_attachment=True, download_name=f"{filename[:-4]}_processed.csv")

@views.route("/database")
@login_required
def database():
    return render_template("database.html", user=current_user)

@views.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        new_username = request.form["username"]
        new_email = request.form["email"]

        user = User.query.filter_by(id=current_user.id).first()
        user.username = new_username
        user.email = new_email
        db.session.commit()
        return redirect(url_for("views.profile"))
    
    return render_template("profile.html", user=current_user)

@views.route("/statistics", methods=["GET", "POST"])
@login_required
def statistics():
    folders = [folder for folder in os.listdir("app/static/reports") if os.path.isdir(os.path.join("app/static/reports", folder))]
    if request.method == "POST":
        selected_folder = request.form["folder"]
        selected_report = os.path.join("app/static/reports", selected_folder, f"{selected_folder}_processed.csv")
        report = pd.read_csv(selected_report)
        return render_template("statistics.html", user=current_user, selected=True, report=report, folders=folders, permissions_list=permissions_list, api_call_signatures=api_call_signatures, intents=intents, keywords=keywords)
    
    return render_template("statistics.html", user=current_user, selected=False, folders=folders)

@views.route("/report")
@login_required
def report():
    return render_template("report.html", user=current_user)


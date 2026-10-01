from flask import Flask, request, render_template
import os

from analyzer import (
    parse_email,
    analyze_url,
    detect_urgent_language,
    calculate_risk,
    analyze_sender
)


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":

        file = request.files.get("email_file")

        if file and file.filename:

            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            file.save(file_path)

            email_data = parse_email(file_path)

            sender_analysis = analyze_sender(
                email_data["sender"]
            )

            url_results = []

            for url in email_data["urls"]:
                url_results.append(
                    analyze_url(url)
                )

            urgent_words = detect_urgent_language(
                email_data["body"]
            )

            score, level, reasons = calculate_risk(
                url_results,
                urgent_words,
                sender_analysis
            )

            result = {
                "sender": email_data["sender"],
                "recipient": email_data["recipient"],
                "subject": email_data["subject"],
                "urls": url_results,
                "urgent_words": urgent_words,
                "score": score,
                "level": level,
                "reasons": reasons
            }

    return render_template(
        "index.html",
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)

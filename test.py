from analyzer import (
    parse_email,
    analyze_url,
    detect_urgent_language,
    calculate_risk,
    analyze_sender
)


result = parse_email("samples/test_email.eml")


print("========== SENDER ANALYSIS ==========")

sender_analysis = analyze_sender(result["sender"])

print("Suspicious:", sender_analysis["suspicious"])

for reason in sender_analysis["reasons"]:
    print("Reason:", reason)


print("\n========== EMAIL ANALYSIS ==========")

print("Sender:", result["sender"])
print("Recipient:", result["recipient"])
print("Subject:", result["subject"])


print("\n========== URL ANALYSIS ==========")

url_results = []

for url in result["urls"]:

    analysis = analyze_url(url)

    url_results.append(analysis)

    print("\nURL:", analysis["url"])
    print("Domain:", analysis["domain"])
    print("Suspicious:", analysis["suspicious"])

    for reason in analysis["reasons"]:
        print("Reason:", reason)


print("\n========== LANGUAGE ANALYSIS ==========")

urgent_words = detect_urgent_language(result["body"])

if urgent_words:

    print("Suspicious words found:")

    for word in urgent_words:
        print("-", word)

else:

    print("No suspicious language found.")


print("\n========== RISK ASSESSMENT ==========")

score, level, reasons = calculate_risk(
    url_results,
    urgent_words,
    sender_analysis
)

print("Risk Score:", score)
print("Risk Level:", level)

print("\nReasons:")

for reason in reasons:
    print("-", reason)

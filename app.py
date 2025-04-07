from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import re
from datetime import datetime

app = Flask(__name__)
CORS(app)  # ✅ Allow any origin

# --------------------------
# ⚠️ Suspicious Patterns
# --------------------------
suspicious_patterns = [
    r'<script.*?>.*?</script>',                      # JS Injection
    r'(select|insert|update|delete|drop|alter)\s',   # SQL keywords
    r'\$\w+\s*:',                                     # NoSQL: $ne, $gt etc
    r'(--|\|\||;)',                                   # SQL comment/chain
    r'(rm\s+-rf|cat\s+/etc/passwd)',                  # Terminal injection
    r'(eval\(|exec\()',                               # Code execution
    r'ObjectId\s*\(',                                 # Mongo injection
    r'window\.location|document\.cookie'              # JS hijacking
]

def check_for_hacks(text):
    """Return list of matched suspicious patterns"""
    return [pattern for pattern in suspicious_patterns if re.search(pattern, text, re.IGNORECASE | re.DOTALL)]

# --------------------------
# Clean & Parse Input
# --------------------------
def clean_json_input(json_str):
    json_str = re.sub(r'//.*?\n', '', json_str)  # Remove JS-style comments
    json_str = re.sub(r'/\*.*?\*/', '', json_str, flags=re.DOTALL)  # Block comments
    json_str = json_str.strip("'\"")  # Remove leading/trailing quotes
    json_str = json_str.replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t')
    return json_str

def handle_mongo_special_fields(data):
    if isinstance(data, dict):
        if '$oid' in data:
            return f"ObjectId('{data['$oid']}')"
        elif '$date' in data:
            try:
                if isinstance(data['$date'], str):
                    dt = datetime.strptime(data['$date'], '%Y-%m-%dT%H:%M:%SZ')
                    return dt.isoformat() + ' (UTC)'
                elif isinstance(data['$date'], int):
                    return datetime.fromtimestamp(data['$date'] / 1000).isoformat() + ' (UTC)'
            except:
                return data['$date']
        return {k: handle_mongo_special_fields(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [handle_mongo_special_fields(item) for item in data]
    return data

# --------------------------
# Main Route
# --------------------------
@app.route('/convert', methods=['POST'])
def beautify_json():
    try:
        req = request.get_json()
        raw_data = req.get('data', '')

        cleaned = clean_json_input(raw_data)

        # Security check: if suspicious, reject early
        suspicious = check_for_hacks(cleaned)
        if suspicious:
            return jsonify({
                "message": "❌ Data cannot be processed due to suspicious patterns detected.",
                "matched_patterns": suspicious
            }), 400

        # Attempt to parse the cleaned string
        try:
            parsed = json.loads(cleaned)
        except:
            try:
                parsed = json.loads(json.loads(cleaned))
            except Exception as e:
                return jsonify({
                    "message": f"❌ Invalid JSON format: {str(e)}"
                }), 400

        # Handle special fields like $oid, $date
        processed = handle_mongo_special_fields(parsed)

        # Beautify final output
        pretty = json.dumps(processed, indent=4, ensure_ascii=False, default=str)

        return jsonify({
            "data": processed,
            "formatted": pretty
        })

    except Exception as e:
        return jsonify({
            "message": f"❌ Error processing request: {str(e)}"
        }), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)

from app import apps
app.run(debug=True, ssl_context=('./ssl.crt', './ssl.key'))

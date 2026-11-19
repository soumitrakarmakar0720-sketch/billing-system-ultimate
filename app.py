import os
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# Other configuration and extensions go here.

# Routes must come after app is initialized.
@app.get("/staff")
def staff():
@auth('admin')
def staff(): return render_template('staff.html', users=User.query.order_by(User.id).all())


@app.post('/staff')
@auth('admin')
def add_staff():
    username = request.form.get('username', '').strip(); password = request.form.get('password', '')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,50}', username) or len(password) < 12: abort(400, 'Username invalid or password shorter than 12 characters')
    if User.query.filter_by(username=username).first(): abort(409, 'Username exists')
    db.session.add(User(username=username, password_hash=generate_password_hash(password), role='staff'))
    log('STAFF_CREATED', details=username); db.session.commit(); return redirect(url_for('staff'))


@app.post('/staff/<int:user_id>/toggle')
@auth('admin')
def toggle_staff(user_id):
    user = db.get_or_404(User, user_id)
    if user.role == 'admin': abort(403)
    user.active = not user.active; log('STAFF_STATUS_CHANGED', details=f'{user.username}: {user.active}'); db.session.commit()
    return redirect(url_for('staff'))


@app.get('/audit')
@auth('admin')
def audit(): return render_template('audit.html', events=Audit.query.order_by(Audit.id.desc()).limit(300).all())


@app.get('/export/orders.csv')
@auth('admin')
def export_orders():
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(['Order', 'Customer', 'Phone', 'Total INR', 'Status', 'Reference', 'Created UTC'])
    for o in Order.query.order_by(Order.id.desc()).all(): writer.writerow([o.order_no, o.customer, o.phone, o.total, o.status, o.payment_ref, o.created_at.isoformat()])
    data = io.BytesIO(output.getvalue().encode('utf-8-sig'))
    return send_file(data, mimetype='text/csv', as_attachment=True, download_name='owl-orders.csv')


def cf_headers():
    return {'x-client-id': CF_ID, 'x-client-secret': CF_SECRET, 'x-api-version': '2023-08-01', 'Content-Type': 'application/json'}


@app.post('/pay/<token>/cashfree')
def cashfree_start(token):
    if not (CF_ID and CF_SECRET): abort(503, 'Cashfree not configured')
    order = order_for_token(token)
    if order.status == 'PAID': abort(409)
    if order.total <= 0: abort(400)
    if not re.fullmatch(r'\d{10}', order.phone or ''):
        flash('A valid 10-digit customer phone is required for online gateway checkout', 'error')
        return redirect(url_for('checkout', token=token))
    if not order.gateway_order_id:
        order.gateway_order_id = 'owlu_' + str(order.id) + '_' + secrets.token_hex(5)
        db.session.commit()
    # Gateway order ID is stable; repeated calls use Cashfree's existing order where possible.
    payload = {'order_id': order.gateway_order_id, 'order_amount': float(order.total), 'order_currency': 'INR', 'customer_details': {'customer_id': f'owl_{order.id}', 'customer_name': order.customer[:100], 'customer_phone': order.phone}, 'order_meta': {'return_url': url_for('checkout', token=token, _external=True)}}
    try:
        response = requests.post(CF_BASE+'/orders', headers=cf_headers(), json=payload, timeout=12)
        if response.status_code == 409:
            response = requests.get(CF_BASE+'/orders/'+order.gateway_order_id, headers=cf_headers(), timeout=12)
        response.raise_for_status(); data = response.json()
    except (requests.RequestException, ValueError) as exc:
        # Do not log credentials, request headers, or full API responses.
        if isinstance(exc, requests.HTTPError) and exc.response is not None:
            app.logger.error('Cashfree create order rejected: HTTP %s', exc.response.status_code)
        else:
            app.logger.exception('Cashfree create order failed')
        flash('Payment gateway unavailable; try again later', 'error')
        return redirect(url_for('checkout', token=token))
    payment_session_id = data.get('payment_session_id')
    if not payment_session_id:
        flash('Gateway did not return a payment session', 'error'); return redirect(url_for('checkout', token=token))
    return render_template('gateway.html', order=order, payment_session_id=payment_session_id, cf_env=CF_ENV)


def verify_cf_webhook(raw, timestamp, signature):
    expected = base64.b64encode(hmac.new(CF_SECRET.encode(), (timestamp.encode()+raw), hashlib.sha256).digest()).decode()
    return bool(CF_SECRET and timestamp and signature and hmac.compare_digest(expected, signature))


@app.post('/webhooks/cashfree')
def cashfree_webhook():
    raw = request.get_data()
    if not verify_cf_webhook(raw, request.headers.get('x-webhook-timestamp', ''), request.headers.get('x-webhook-signature', '')): abort(401)
    try: data = request.get_json(force=True)
    except Exception: abort(400)
    info = data.get('data') or {}; order_info = info.get('order') or {}; payment = info.get('payment') or {}
    gateway_id = order_info.get('order_id'); payment_status = payment.get('payment_status')
    if not gateway_id: return jsonify(ok=True)
    order = Order.query.filter_by(gateway_order_id=gateway_id).first()
    if not order: return jsonify(ok=True)
    # Cashfree amount must be compared to the original order; never trust a browser redirect.
    try: received = money(payment.get('payment_amount', '-1'))
    except (InvalidOperation, ValueError): received = D('-1')
    if payment_status != 'SUCCESS' or received != money(order.total): return jsonify(ok=True)
    event_id = str(payment.get('cf_payment_id') or '')
    if not event_id: return jsonify(ok=True)
    event_key = hashlib.sha256(f'{gateway_id}:{event_id}:SUCCESS'.encode()).hexdigest()
    if WebhookEvent.query.filter_by(event_key=event_key).first(): return jsonify(ok=True)
    db.session.add(WebhookEvent(event_key=event_key))
    if order.status != 'PAID':
        order.status = 'PAID'; order.payment_ref = event_id
        log('GATEWAY_PAYMENT_CONFIRMED', order, event_id, actor='cashfree')
    db.session.commit()
    return jsonify(ok=True)


@app.get('/health')
def health():
    try: db.session.execute(db.text('SELECT 1'))
    except Exception: return jsonify(status='error'), 503
    return jsonify(status='ok')


@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Cache-Control'] = 'no-store' if request.endpoint in ('login', 'checkout', 'orders', 'dashboard') else 'private'
    return resp


@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    print('Database tables created. Next run flask create-admin.')


@app.cli.command('create-admin')
def create_admin_command():
    username = os.environ.get('ADMIN_USERNAME', '').strip(); password = os.environ.get('ADMIN_PASSWORD', '')
    if not username or len(password) < 12: raise RuntimeError('Set ADMIN_USERNAME and ADMIN_PASSWORD (12+ characters)')
    user = User.query.filter_by(username=username).first()
    if user: raise RuntimeError('User exists; not overwriting password')
    db.session.add(User(username=username, password_hash=generate_password_hash(password), role='admin'))
    db.session.commit(); print('Admin created')


if __name__ == '__main__':
    app.run(port=int(os.environ.get('PORT', 5000)))

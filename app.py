"""OWL STORE Ultimate: deployable Flask billing, staff, customer portal, gateway checkout."""
import base64
import csv
import hashlib
import hmac
import io
import os
import re
import secrets
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps
from urllib.parse import quote, urlparse

import qrcode
import requests
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

D = Decimal
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', ''),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///owlstore-ultimate.db').replace('postgres://', 'postgresql+psycopg://', 1).replace('postgresql://', 'postgresql+psycopg://', 1),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '1') == '1',
    MAX_CONTENT_LENGTH=1024 * 1024,
)
if not app.config['SECRET_KEY'] or app.config['SECRET_KEY'] == 'change-me':
    raise RuntimeError('Set a strong SECRET_KEY environment variable')
db = SQLAlchemy(app)
UPI_ID = os.environ.get('UPI_ID', 'owlstore@ybl')
UPI_NAME = os.environ.get('UPI_NAME', 'OWL STORE')
CF_ID = os.environ.get('CASHFREE_CLIENT_ID', '')
CF_SECRET = os.environ.get('CASHFREE_CLIENT_SECRET', '')
CF_ENV = os.environ.get('CASHFREE_ENV', 'sandbox')
CF_BASE = 'https://api.cashfree.com/pg' if CF_ENV == 'production' else 'https://sandbox.cashfree.com/pg'


def now(): return datetime.now(timezone.utc)
def money(v): return D(str(v)).quantize(D('.01'), rounding=ROUND_HALF_UP)
def rupees(v): return f'{money(v):,.2f}'
app.jinja_env.filters['rupees'] = rupees


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')
    active = db.Column(db.Boolean, default=True, nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    sku = db.Column(db.String(100), default='')
    price = db.Column(db.Numeric(12, 2), nullable=False)
    stock = db.Column(db.Integer, default=0, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_no = db.Column(db.String(45), unique=True, nullable=False)
    customer = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), default='')
    email = db.Column(db.String(200), default='')
    subtotal = db.Column(db.Numeric(12, 2), nullable=False)
    discount = db.Column(db.Numeric(12, 2), default=0)
    tax_rate = db.Column(db.Numeric(6, 2), default=0)
    tax = db.Column(db.Numeric(12, 2), default=0)
    total = db.Column(db.Numeric(12, 2), nullable=False)
    status = db.Column(db.String(30), default='PENDING', nullable=False)
    payment_ref = db.Column(db.String(120), default='')
    payment_reported_at = db.Column(db.DateTime(timezone=True))
    rejection_reason = db.Column(db.String(300), default='')
    public_token = db.Column(db.String(90), unique=True, nullable=False)
    gateway_order_id = db.Column(db.String(90), unique=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan', lazy='select')


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, nullable=True)
    name = db.Column(db.String(200), nullable=False)
    qty = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(12, 2), nullable=False)

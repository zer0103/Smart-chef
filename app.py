from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dish_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref='favorites')


# Forms
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "اسم المستخدم"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)],
                             render_kw={"placeholder": "كلمة المرور"})

    submit = SubmitField('إنشاء حساب')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('اسم المستخدم موجود بالفعل')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "اسم المستخدم"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)],
                             render_kw={"placeholder": "كلمة المرور"})

    submit = SubmitField('تسجيل الدخول')


# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/favorites', methods=['GET', 'POST'])
def favorites():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash("يرجى تسجيل الدخول لإضافة عناصر إلى المفضلة", "warning")
            return redirect(url_for('login'))

        dish_name = request.form.get('dish_name')
        if dish_name:
            new_favorite = Favorite(dish_name=dish_name, user_id=current_user.id)
            db.session.add(new_favorite)
            db.session.commit()
            flash('تمت إضافة الأكلة إلى المفضلة', 'success')
        return redirect(url_for('favorites'))

    user_favorites = []
    if current_user.is_authenticated:
        user_favorites = Favorite.query.filter_by(user_id=current_user.id).all()

    return render_template('favorites.html', favorites=user_favorites)


@app.route('/delete_favorite/<int:id>', methods=['POST'])
@login_required
def delete_favorite(id):
    favorite = Favorite.query.get_or_404(id)
    if favorite.user_id != current_user.id:
        flash("ليس لديك صلاحية لحذف هذا العنصر", "danger")
        return redirect(url_for('favorites'))

    db.session.delete(favorite)
    db.session.commit()
    flash("تم حذف العنصر من المفضلة", "success")
    return redirect(url_for('favorites'))


# ✅ صفحة الملف الشخصي
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username)


# إنشاء الجداول وتشغيل التطبيق
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
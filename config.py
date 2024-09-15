class Config:
    SECRET_KEY = 'your_secret_key'  # Change to a secure key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SESSION_TYPE = 'filesystem'

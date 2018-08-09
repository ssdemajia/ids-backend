## datebase to model
first install the flask-sqlacodegen, pymysql, flask-sqlalchemy

```python
flask-sqlacodegen --outfile model.py --flask mysql://[username]:[password]@[ip address]/[datebase name]
```

open mongod
```bash
mongod --log-path=/var/log/mongodb/log --fork
```
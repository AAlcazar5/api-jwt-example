const bodyParser = require('body-parser');
const express = require('express');
const jsonwebtoken = require('jsonwebtoken');
const scrypt = require('scrypt');

// NEW: MySQL database driver
const mysql = require('mysql2/promise');

const app = express();

// Use `process.env` here, instead of a hard-coded value
const port = 3000;

// We import and immediately load the `.env` file
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.use(async function mysqlConnection(req, res, next) {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    await next();

    req.db.release();
  } catch (e) {
    // If anything downstream throw an error, we must release the connection allocated for the request
    if (req.db) req.db.release();
    throw e;
  }
});

app.use(bodyParser.json());

app.get('/', async function (req, res) {
  const [cars] = await req.db.query(`
    SELECT c.id, c.model, m.name AS make_name
    FROM car c
    LEFT JOIN car_make m
    ON c.make_id = m.id
  `);

  res.json(cars);
});

app.use(async function (req, res, next) {
  if (!req.headers.authorization) {
    throw new Error('Authorization header is required');
  }

  const [scheme, token] = req.headers.authorization.split(' ');

  if (scheme !== 'Bearer') {
    throw new Error('Invalid authorization');
  }

  try {
    const payload = jsonwebtoken.verify(token, process.env.JWT_KEY);
    req.user = payload;
  } catch (err) {
    throw new Error(err);
  }

  await next();
});

app.post('/', async function (req, res) {
  const [cars] = await req.db.query(
    `
    INSERT INTO car (created_user_id, make_id, model, date_created)
    VALUES (:created_user_id, :make_id, :model, NOW())
  `,
    {
      created_user_id: req.user.sub,
      make_id: req.body.make_id,
      model: req.body.model,
    }
  );

  res.json(cars);
});

app.post('/auth/register', async function (req, res) {
  const hashedPassword = scrypt.kdfSync(req.body.password, {
    N: +process.env.SCRYPT_N_VAL,
    r: +process.env.SCRYPT_R_VAL,
    p: +process.env.SCRYPT_P_VAL,
  });

  const [stmt] = await req.db.query(
    `
    INSERT INTO user (email, password)
    VALUES (:email, :hashedPassword)
  `,
    {
      email: req.body.email,
      hashedPassword,
    }
  );

  res.json(stmt);
});

app.post('/auth/login', async function (req, res) {
  const [[user]] = await req.db.query(
    `SELECT * FROM user WHERE email = :email`,
    {
      email: req.body.email
    }
  );

  const match = await scrypt.verifyKdf(Buffer.from(user.password, 'base64'), req.body.password);

  if (match) {
    const payload = {
      sub: user.id
    };

    const token = jsonwebtoken.sign(payload, process.env.JWT_KEY, {
      expiresIn: '24h'
    });

    res.json({
      jwt: token
    });
  } else {
    res.json('Nice try, dummy');
  }
});

app.put('/:id', async function (req, res) {
  const [cars] = await req.db.query(
    `
    UPDATE car SET model = :model WHERE id = :id
  `,
    {
      model: req.body.model,
      id: req.params.id,
    }
  );

  res.json(cars);
});

app.delete('/:id', async function (req, res) {
  const [cars] = await req.db.query(
    `
    DELETE FROM car WHERE id = :id
  `,
    {
      id: req.params.id,
    }
  );

  res.json(cars);
});

app.listen(port, () => console.log(`Demo app listening at http://localhost:${port}`));

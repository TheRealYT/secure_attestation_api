const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const morgan = require('morgan');
const compression = require('compression');
const helmet = require('helmet');
const {rateLimit} = require('express-rate-limit');
const {protect, sessionGenerator, sessionValidator} = require('./middlewares');
const {logger} = require('./logger');

const publicDir = path.join(__dirname, 'public');
const app = express();
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'logs', 'access.log'), {flags: 'a'});

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  ipv6Subnet: 56,
}));
app.use(helmet());
app.use(compression());
app.use(express.static(publicDir));

app.get('/', (req, res) => {
  return res.sendFile(path.join(__dirname, 'index.html'));
});

app.use(morgan('combined', {stream: accessLogStream}));

app.post('/get-session', sessionGenerator);

app.post('/protected-route', sessionValidator, protect, (req, res) => {
  return res.send('Protected content accessed!\n Now, do your best whether using reveres-engineering or whatever, to access \n/secret-route\nOf course you will be rewarded');
});

app.post('/secret-route', sessionValidator, protect, (req, res) => {
  return res.send(`You got the secret ${req.context}!\nSubmit it to https://t.me/TheRecepientRobot`);
});

app.use((req, res) => {
  res.status(404).send('Not found');
});

app.use((err, req, res, _) => {
  logger.error(`Internal Error ${req.context}`, err);

  if (!res.headersSent)
    res.status(500).send('Internal Error');
});

app.listen(process.env.PORT ?? 3000, () => console.log('Started'));

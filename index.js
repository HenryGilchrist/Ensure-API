import express from 'express';
import cors from 'cors';
import Joi from 'joi';
import qs from 'qs';
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import cookieParser from 'cookie-parser';
import env from 'dotenv'
env.config();

import { SessionPool } from './db.js';

// API Parsing Settings

const app = express();
app.use(express.json());

const allowedOrigins = [
  'https://henrygilchrist.github.io/Ensure/',
  'https://henrygilchrist.github.io'
];

app.use(cors({
  origin: function(origin, callback){
    if(!origin) return callback(null, true);

    if(allowedOrigins.indexOf(origin) !== -1){
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.set("query parser", str => qs.parse(str));
app.use(cookieParser());


// Query String Handling 

const valueIsNumber = (value) => !isNaN(Number(value));

function valueIsDateString(value) {
  const regex = /^\d{4}-\d{2}-\d{2}$/;
  return regex.test(value);
}

function validateProperty(property){
  if (!reviewProperties.includes(property)) {
      throw new Error(`Invalid property name: ${property} for filtering`);
    }
}

function validateOperator(operator){
  if (!(operator in filterSqlOperationsMap)) {
        throw new Error(`Invalid operator: ${operator}`);
      }
}

function validateAndConvertFilterValue(value, operator){
  const error = `Invalid operator ${operator} for value ${value}`;

  if (valueIsNumber(value)) return Number(value);
  
  if(valueIsDateString(value)){
    if(!['gte','lte'].includes(operator)) throw new Error(error);
    else return new Date(value);
  }
  
  // Boolean and String values
  if(operator != 'eq') throw new Error(error);

  if (['true','false'].includes(value)) return Boolean(value);
  else return value;
}

const reviewProperties = ["review","name","rating","date", "policy"];

const filterSqlOperationsMap = {
  gt: '>',
  lt: '<',
  gte: '>=',
  lte: '<=',
  eq: '='
}

function createFilterConditionsAndVals(filters) {
  const filterConditions = [];
  const filterValues = [];

  let filterCount = 0;
  
  Object.entries(filters).forEach(([property, operations]) => {

    validateProperty(property);

    Object.entries(operations).forEach(([operator, value]) => {
      
      validateOperator(operator);

      value = validateAndConvertFilterValue(value, operator);

      filterConditions.push(`"${property}" ${filterSqlOperationsMap[operator]} $${++filterCount}`);
      filterValues.push(value)
    });
  });
  
  return {filterConditions, filterValues, filterCount};
}

// Make Query Function

async function getQueryResponse(queryString, queryVals = []){
  try {
    const res = queryVals.length > 0 ? await SessionPool.query(queryString, queryVals) : await SessionPool.query(queryString);
    return {rows: res.rows, rowCount: res.rowCount};
  }
  catch(error){
    error.queryString = queryString;
    error.queryVals = queryVals;
    throw error;
  }
}

// Endpoint Logic

app.get('/reviews/count', async (req,res) => {
    const result = await getQueryResponse('SELECT Count(id) from "Reviews"');
    return res.status(200).send({success: true, count: parseInt(result.rows[0].count)});
})

app.get('/reviews', async (req,res) => {

  if(Object.keys(req.query).length == 0){
    const { rows, rowCount } = await getQueryResponse('SELECT * FROM "Reviews"');
    return res.status(200).send({success: true, data: rows, length: rowCount});
  }

  const { page, limit, sort, order="desc", filter}  = req.query;

  let [filterString, sortString, paginationString] = ['','',''];
  let [filterVals, paginationVals] = [[],[]];
  let valueCounter = 0;

  if(filter){

    if(typeof filter !== 'object' && !Array.isArray(filter)){
      return res.status(400).send({success: false, message: "API Response: Must provide filter object: filter[property][operation]=value", filter: filter, reviewProperties: reviewProperties, filterOperations: filterSqlOperationsMap});
    }

    try{
      const { filterValues: newFilterVals, filterConditions, filterCount } = createFilterConditionsAndVals(filter);
      
      filterVals = newFilterVals;

      valueCounter += filterCount;

      filterString = 'WHERE ' + filterConditions.join(' AND ') + ' ';
    }
    catch(error){
      return res.status(400).send({success: false, message: "API Response: " + error.message, filter: filter, reviewProperties: reviewProperties, filterOperations: filterSqlOperationsMap});
    }
  }

  if(sort){
    if(Array.isArray(sort) || sort.length == 0){
      return res.status(400).send({success: false, message: "API Response: Can only sort by a single property", sort: sort});
    }

    if(reviewProperties.includes(sort)){
      let orderList = ["asc", "desc"];
      let orderChoice = orderList.indexOf(order);
      if(orderChoice == -1){
        return res.status(400).send({success: false, message: "API Response: Must provide valid order direction", order: order, orderOptions: orderList});
      }
      else{
        sortString = `ORDER BY ${sort} ${orderList[orderChoice]} `;
      }
    }
    else{
      return res.status(400).send({success: false, message: "API Response: Must provide valid property to sort by", reviewProperties: reviewProperties});
    }
  }

  if(page !== undefined && limit !== undefined){

    const pageNum = parseInt(page);
    const pageLimit = parseInt(limit);

    if(Number.isNaN(pageNum) || Number.isNaN(pageLimit)){
      return res.status(400).send({success: false, message: "API Response: Page number and limit must be numeric", page: page, limit: limit});
    }

    if(pageNum < 1 || pageLimit < 1){
      return res.status(400).send({success: false, message: "API Response: Page number and limit must be greater than 0", page: page, limit: limit});
    }

    const pageStartIndex = (pageNum - 1) * pageLimit;

    paginationString = `LIMIT $${++valueCounter} OFFSET $${++valueCounter}`;
    paginationVals = [pageLimit, pageStartIndex];
  }

  const getCountQueryString = 'SELECT Count(id) FROM "Reviews" ' + filterString;
  const { rows: [{count: totalReviews}] } = await getQueryResponse(getCountQueryString, filterVals);

  const getReviewsQueryString = 'SELECT * FROM "Reviews" ' + filterString + sortString + paginationString;
  const getReviewsQueryVals = [...filterVals, ...paginationVals];

  const { rows, rowCount } = await getQueryResponse(getReviewsQueryString, getReviewsQueryVals);

  if(rowCount == 0){
    let message;

    if (paginationVals.length == 0){
      const [pageLimit, startIndex] = paginationVals;
      const pageNum = startIndex == 0 ? 1 : (startIndex / pageLimit) + 1;

      message = `Page ${pageNum} does not exist with page size ${pageLimit}`;
    }
    else message = "No reviews match the applied filters";

    return res.status(404).send({success: false, message: message, data: [], length: 0});
  }
  
  return res.status(200).send({success: true, data: rows, length: totalReviews});
})

// Joi Schema:

const firstCharLetterRegex = /^[A-Za-z]/;
const allowedCharsRegex = /^[A-Za-z&+'. ]*$/;

function firstCharLetterSchema(propertyName, valueRangeObj = {}){
    let schema = Joi.string();

    if(Object.keys(valueRangeObj).length > 0){
        schema = schema.ruleset;
        
        if(Number.isInteger(valueRangeObj.min)){
            schema = schema.min(valueRangeObj.min)
        }

        if(Number.isInteger(valueRangeObj.max)){
            schema = schema.max(valueRangeObj.max)
        }

        schema = schema.message(`${propertyName} must be ${valueRangeObj.max == undefined ? `at least ${valueRangeObj.min}` : `between ${valueRangeObj.min || 1} and ${valueRangeObj.max}`} characters`)
    }

    schema = schema.pattern(firstCharLetterRegex);
    schema = schema.message(`${propertyName} must begin with a letter`);

    return schema;
}


const loginSchema = Joi.object({
  username: firstCharLetterSchema("Username", {min: 3, max: 15}).required(),
  password: firstCharLetterSchema("Password", {min: 7, max: 24}).required()
}).unknown(false)

const postReviewSchema = Joi.object({

  name: firstCharLetterSchema("Name", {min: 3, max: 25})
    .required()
    .pattern(allowedCharsRegex)
    .message("Name can only contain special characters: [&, +, ' and .]"),

  userID: Joi.number()
    .required()
    .integer()
    .min(1),

  review: firstCharLetterSchema("Review", {min: 4, max: 300})
    .required(),

  rating: Joi.number()
    .required()
    .label("Rating")
    .min(0.5)
    .max(5)
    .custom((value, helpers) => {
      const decimalPart = value - Math.floor(value);

      if (decimalPart !== 0 && decimalPart !== 0.5) {
        return helpers.error('invalidDecimal');
      }

      return value;
    })
    .messages({
      'invalidDecimal': "Rating must be a whole number or end with .5"
    }),
    

  policy: Joi.string()
    .valid('Term Insurance', 'Joint Life Insurance', 'Serious Illness Cover')
    .label("Policy Type")
    .required(),

}).unknown(false);

// Post Requests

function createJWTToken(payloadObj, secretKey, expiry){
  return jwt.sign(payloadObj, secretKey, {...(expiry !== undefined && {expiresIn: expiry})});
}

function createAccessToken(payloadObj){
  return createJWTToken(payloadObj, process.env.ACCESS_SECRET_KEY, "25s");
}

app.post('/users/register', async (req,res) => {
  const body = req.body;
  if(Object.keys(body).length < 2) return res.status(400).send({success: false, message: "API Response: Must provide username and password"});

  const { error } = loginSchema.validate(body);

  if(error) return res.status(400).send({success: false, message: "API Response: " + error.message});

  const { rowCount } = await getQueryResponse('SELECT 1 FROM "Users" WHERE username = $1', [body.username]);
  
  if(rowCount > 0) return res.status(409).send({success: false, message: "API Response: Username is already taken"});

  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(body.password, salt);

    const { rows } = await getQueryResponse('INSERT INTO "Users" (username, "passwordHash") VALUES ($1, $2) RETURNING id', [body.username, hashedPassword]);
    const userID = rows[0].id;

    return res.status(200).send({success: true, message: `API Response: Account ${userID} successfully created`});
  }
  catch(error) {
    console.error(error);
    return res.status(500).send({success: false, message: "API Response: " + error.message});
  }
})

function validateAccessToken(req, res, next){
  const accessToken = req.cookies.accessToken;
  if(accessToken == undefined) return res.status(401).send({success: false, message: "API Response: Must provide access token"})
  
  jwt.verify(accessToken, process.env.ACCESS_SECRET_KEY, (error, payload) => {

    if(error) return res.status(401).send({success: false, message: "API Response: Access token is invalid", invalidToken: accessToken});
      
    req.payload = payload;
    next();
  })
}

app.post('/users/login', async (req,res) => {
  const body = req.body;
  if(Object.keys(body).length == 0) return res.status(400).send({success: false, message: "API Response: Must provide username and password"});

  const { rows, rowCount } = await getQueryResponse('SELECT * FROM "Users" WHERE username = $1',[body.username]);
  
  if(rowCount == 0) return res.status(404).send({success: false, message: "API Response: Username doesn't exist"});

  const userObj = rows[0];

  try{
    const passwordMatches = await bcrypt.compare(body.password, userObj.passwordHash);
    if(!passwordMatches) return res.status(400).send({success: false, message: "API Response: Password is incorrect"});

    const payload = {userID: userObj.id, username: userObj.username, loginToken: true};
    const accessToken = createAccessToken(payload);
    const refreshToken = createJWTToken(payload, process.env.REFRESH_SECRET_KEY, "1d");
    
    await getQueryResponse('INSERT INTO "RefreshTokens" (token) VALUES ($1)',[refreshToken]);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      sameSite: 'none',
      secure: true
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      sameSite: 'none',
      secure: true
    });
    return res.status(200).send({success: true, message: "API Response: Successfully logged in. Tokens issued in HTTP-Only cookies", userID: payload.userID});
  }
  catch(error){
   return res.status(500).send({success: false, message: "API Response: " + error.message});
  }
})

async function removeRefreshToken(refreshToken){
  await getQueryResponse('DELETE FROM "RefreshTokens" WHERE token = $1',[refreshToken]);
}

app.post('/users/logout', validateAccessToken, async (req,res) => {
  const refreshToken = req.cookies.refreshToken;
  await removeRefreshToken(refreshToken);

  res.clearCookie('accessToken',{
    httpOnly: true,
    sameSite: 'none',
    secure: true
  })
  res.clearCookie('refreshToken',{
    httpOnly: true,
    sameSite: 'none',
    secure: true
  })
  return res.status(200).send({success: true, message: "API Response: Clear request made for token cookies. Ensure credentials = 'include'"});
})

app.post(['/token','/users/me'], async (req,res) => {
  const refreshToken = req.cookies.refreshToken;
  if(refreshToken == undefined) return res.status(400).send({success: false, message: "API Response: Please login"});

  const { rowCount } = await getQueryResponse('SELECT token FROM "RefreshTokens" WHERE token = $1',[refreshToken]);

  if(rowCount == 0) return res.status(401).send({success: false, message: "API Response: Refresh token doesn't exist"});

  jwt.verify(refreshToken, process.env.REFRESH_SECRET_KEY, async (error, payload) => {

    if(error){
      await removeRefreshToken(refreshToken);
      return res.status(403).send({success: false, message: "API Response: Refresh token is no longer valid. Please Login"});
    } 
      
    const newAccessToken = createAccessToken({userID: payload.userID, username: payload.username});

    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      sameSite: 'none',
      secure: true
    });

    return res.status(200).send({success: true, message: "API Response: New access token issued in HTTP-Only cookie. User ID returned in response body", userID: payload.userID, });
  }) 
});

app.post('/reviews', validateAccessToken, async (req,res) =>{
    const review = {userID: req.payload.userID, ...req.body};
    const { error, value } = postReviewSchema.validate(review, {abortEarly: false});

    if (error !== undefined)  return res.status(400).send({success: false, message: "API Response: " + error.message});

    const reviewVals = [value.review, value.name, value.rating, value.userID, value.policy]

    const { rows: [{id: reviewID}] } = await getQueryResponse('INSERT INTO "Reviews" (review, name, rating, "userID", policy) VALUES ($1, $2, $3, $4, $5) RETURNING id', reviewVals);

    return res.status(200).send({success: true, message: `Review ${reviewID} Posted Successfully`}); 
})

async function validateReviewAlteration(req, res, next){
   const reviewID = Number(req.params.id);
    if(!Number.isInteger(reviewID)) return res.status(404).send({success: false, message: "API Response: Must provide integer review ID"});

    const { rows, rowCount } = await getQueryResponse('SELECT * FROM "Reviews" WHERE id = $1', [reviewID]);
    const review = rows[0];
    
    if(rowCount == 0) return res.status(404).send({success: false, message: `Review ${reviewID} doesn't exist`});

    if(review.userID != req.payload.userID) return res.status(403).send({success: false, message: "API Response: Cannot edit review that doesn't belong to you"});

    req.reviewID = review.id;
    next();
}

app.put('/reviews/:id', validateAccessToken, validateReviewAlteration, async (req, res) => {
    const review = {userID: req.payload.userID, ...req.body};
    const { error, value } = postReviewSchema.validate(review, {abortEarly: false});

    if (error) return res.status(400).send({success: false, message: "API Response: " + error.message});


    const reviewVals = [value.review, value.name, value.rating, value.userID, value.policy];
    await getQueryResponse(`UPDATE "Reviews" SET review = $1, name = $2, rating = $3, "userID" = $4, policy = $5 WHERE id = ${req.reviewID}`, reviewVals);

    return res.status(200).send({success: true, message: `Review ${req.reviewID} updated successfully`});
})

app.delete('/reviews/:id', validateAccessToken, validateReviewAlteration, async (req,res) => {
  await getQueryResponse(`DELETE FROM "Reviews" WHERE id = ${req.reviewID}`);

  return res.status(200).send({success: true, message: `Review ${req.reviewID} has been deleted`});
})

// Global Error Handler

app.use((error, req, res, next) => {
  res.status(500).send({success: false, message: error.message || "API Response: Postgres DB Error", data: error});
})

export default app;
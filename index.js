import express from 'express';
import cors from 'cors';
import Joi from 'joi';
import qs from 'qs';
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import cookieParser from 'cookie-parser';
import env from 'dotenv'
env.config();


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

// Import Data
import { reviews, reviewProperties  } from './data/reviews.js';
import { users } from './data/users.js'
import { refreshTokens } from './data/refreshTokens.js'
let userIDCounter = 0;
let reviewIdCounter = reviews.length;

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
  if (!Object.values(filterOperations).includes(operator)) {
        throw new Error(`Invalid operator: ${operator} for property: ${property}`);
      }
}

function validateStringFilter(value, operator){
  const error = `Invalid value of ${value} for ${operator} operation on property ${property}`;

  if(!valueIsDateString(value)){
    if(operator != 'eq') throw new Error(error);
  }
  else{
    if(!['gte','lte'].includes(operator)) throw new Error(error);
  }
}

const filterOperations = {
  greaterThan: 'gt',
  lessThan: 'lt',
  greaterThanOrEqual: 'gte',
  lessThanOrEqual: 'lte',
  equal: 'eq'
}

function createFilterFunctions(filters) {
  const filterFunctions = [];
  
  Object.entries(filters).forEach(([property, operations]) => {

    validateProperty(property);

    Object.entries(operations).forEach(([operator, value]) => {
      
      validateOperator(operator);
      if(!valueIsNumber(value)) validateStringFilter(value, operator);

      switch (operator) {
        case 'gt': 
          filterFunctions.push(item => item[property] > parseFloat(value));
          break;
        case 'lt':
          filterFunctions.push(item => item[property] < parseFloat(value));
          break;
        case 'gte':
          if(valueIsDateString(value)){
            filterFunctions.push(item => item[property] >= new Date(value));
          }
          else{
            filterFunctions.push(item => item[property] >= parseFloat(value));
          }
          break;
        case 'lte':
          if(valueIsDateString(value)){
            filterFunctions.push(item => item[property] <= new Date(value));
          }
          else{
            filterFunctions.push(item => item[property] <= parseFloat(value));
          }
          break;
        case 'eq':
          const valueArr = Array.isArray(value) ? value : [value];

          filterFunctions.push(item => {
            return valueArr.some(v => {
              if (valueIsNumber(v) && valueIsNumber(item[property])) {
                return parseFloat(item[property]) === parseFloat(v);
              }

              return String(item[property]).toUpperCase() === String(v).toUpperCase();
            });
          });
          break;
      }
    });
  });
  
  return filterFunctions;
}

function sortResourceAsc(data, propertyName){
  if(data.length == 0) return data;
  
  const firstValue = data[0][propertyName];
  const isString = typeof firstValue === 'string';

  if (isString) return data.sort((a,b) => a[propertyName].localeCompare(b[propertyName]));
  else return data.sort((a,b) => a[propertyName] - b[propertyName]);
}

function sortResourceDesc(data, propertyName){
  if(data.length == 0) return data;
  
  const firstValue = data[0][propertyName];
  const isString = typeof firstValue === 'string';

  if (isString) return data.sort((a,b) => b[propertyName].localeCompare(a[propertyName]));
  else return data.sort((a,b) => b[propertyName] - a[propertyName]);
}


app.get('/reviews/count', (req,res) => {
    return res.status(200).send({length: reviews.length});
})

app.get('/reviews', (req,res) => {

  let reviewData = [...reviews];

  if(Object.keys(req.query).length == 0){
    return res.status(200).send({success: true, data: reviews, length: reviewData.length});
  }

  const { page, limit, sort, order="desc", filter}  = req.query;
  

  if(filter){

    if(typeof filter !== 'object' && !Array.isArray(filter)){
      return res.status(400).send({success: false, message: "API Response: Must provide filter object: filter[property][operation]=value", filter: filter, reviewProperties: reviewProperties, filterOperations: filterOperations});
    }

    try{
      const filterFunctions = createFilterFunctions(filter);
      reviewData = reviewData.filter(item => 
        filterFunctions.every(filterFn => filterFn(item))
      );
    }
    catch(error){
      return res.status(400).send({success: false, message: "API Response: " + error.message, filter: filter, reviewProperties: reviewProperties, filterOperations: filterOperations});
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
        reviewData = orderChoice == 0 ? sortResourceAsc(reviewData, sort) : sortResourceDesc(reviewData, sort);
      }
    }
    else{
      return res.status(400).send({success: false, message: "API Response: Must provide valid property to sort by", reviewProperties: reviewProperties});
    }
  }

  if(page == null && limit == null){
    return res.status(200).send({success: true,length: reviewData.length, data: reviewData});
  }

  const pageNum = parseInt(page);
  const pageLimit = parseInt(limit);

  if(Number.isNaN(pageNum) || Number.isNaN(pageLimit)){
    return res.status(400).send({success: false, message: "API Response: Page number and limit must be numeric", page: page, limit: limit});
  }

  if(pageNum < 1 || pageLimit < 1){
    return res.status(400).send({success: false, message: "API Response: Page number and limit must be greater than 0", page: page, limit: limit});
  }


  const pageStartIndex = (pageNum - 1) * pageLimit;
  
  if(pageStartIndex > reviewData.length - 1){
    const message = pageStartIndex == 0 ? "No reviews match the applied filters" : `Page ${pageNum} does not exist with page size ${pageLimit}`;

    return res.status(404).send({success: false, message: message, data: [], length: 0});
  }

  return res.status(200).send({success: true, length: reviewData.length, data: reviewData.slice(pageStartIndex, pageStartIndex + pageLimit), message: `Returning page ${pageNum} of limit ${pageLimit}`});
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

  const { error, value } = loginSchema.validate(body);

  if(error) return res.status(400).send({success: false, message: "API Response: " + error.message});

  const sameUsername = users.find((user) => user.username == value.username);
  if(sameUsername !== undefined) return res.status(409).send({success: false, message: "API Response: Username is already taken"});

  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(body.password, salt);
    const userID = ++userIDCounter;
    const user = {userID: userID, username: body.username, passwordHash: hashedPassword};
    users.push(user);
    return res.status(200).send({success: true, message: "API Response: Account successfully created"})
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
  if(Object.keys(body).length == 0) return res.status(400).send({success: false, message: "API Response: Must provide username and password"}) 

  const userObj = users.find((user) => user.username == body.username);
  if(userObj == undefined) return res.status(404).send({success: false, message: "API Response: Username doesn't exist"})

  try{
    const passwordMatches = await bcrypt.compare(body.password, userObj.passwordHash);
    if(!passwordMatches) return res.status(400).send({success: false, message: "API Response: Password is incorrect"});

    const payload = {userID: userObj.userID, username: userObj.username, loginToken: true};
    const accessToken = createAccessToken(payload);
    const refreshToken = createJWTToken(payload, process.env.REFRESH_SECRET_KEY, "1d");
    refreshTokens.push(refreshToken);

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
    return res.status(200).send({success: true, message: "API Response: Successfully logged in. Tokens issued in HTTP-Only cookies", userID: userObj.userID});
  }
  catch(error){
   return res.status(500).send({success: false, message: "API Response: " + error.message});
  }
})

function removeRefreshToken(refreshToken){
  const tokenIndex = refreshTokens.findIndex((token) => token == refreshToken);
  if(refreshToken !== -1){
    refreshTokens.splice(tokenIndex, 1);
  }
}

app.post('/users/logout', validateAccessToken, (req,res) => {
  const refreshToken = req.cookies.refreshToken;
  removeRefreshToken(refreshToken);

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
  return res.status(200).send({success: true, message: "API Response: Clear request made for token cookies. Ensure credentials = 'include"});
})

app.post(['/token','/users/me'], (req,res) => {
  const refreshToken = req.cookies.refreshToken;
  if(refreshToken == undefined) return res.status(400).send({success: false, message: "API Response: Please login"});
  if(!refreshTokens.includes(refreshToken)) return res.status(401).send({success: false, message: "API Response: Refresh token doesn't exist"});
  jwt.verify(refreshToken, process.env.REFRESH_SECRET_KEY, (error, payload) => {

    if(error){
      removeRefreshToken(refreshToken);
      return res.status(403).send({success: false, message: "API Response: Refresh token is no longer valid. Please Login"});
    } 
      
    const newAccessToken = createAccessToken({userID: payload.userID, username: payload.username});

    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      sameSite: 'none',
      secure: true
    });
    return res.status(200).send({success: true, message: "API Response: New access token issued in HTTP-Only cookie. User ID returned in response body", userID: payload.userID});
  }) 
});

app.post('/reviews', validateAccessToken, (req,res) => {
    const review = {userID: req.payload.userID, ...req.body};
    const { error, value } = postReviewSchema.validate(review, {abortEarly: false});

    if (!error){
        reviewIdCounter++;
        reviews.push({id: reviewIdCounter, ...value, date: new Date()});
        return res.status(200).send({success: true, data: reviews, message: `Review Posted Successfully`});
    }
    else{
      return res.status(400).send({success: false, message: "API Response: " + error.message});
    }  
})

function validateReviewAlteration(req, res, next){
   const reviewID = Number(req.params.id);
    if(!Number.isInteger(reviewID)) return res.status(404).send({success: false, message: "API Response: Must provide integer review ID"});

    const reviewIndex = reviews.findIndex((review) => review.id == reviewID);
    if(reviewIndex == -1) return res.status(404).send({success: false, message: `Review ${reviewID} doesn't exist`});

    if(!reviews[reviewIndex].userID == req.payload.userID) return res.status(403).send({success: false, message: "API Response: Cannot edit review that doesn't belong to you"});

    req.reviewIndex = reviewIndex;
    req.reviewID = reviewID;
    next();
}

app.put('/reviews/:id', validateAccessToken, validateReviewAlteration, (req, res) => {
    const review = {userID: req.payload.userID, ...req.body};
    const { error, value } = postReviewSchema.validate(review, {abortEarly: false});

    if (!error){
      const completeReview = {id: req.reviewID, ...value, date: new Date()};
      reviews[req.reviewIndex] = completeReview;
      return res.status(200).send({success: true, message: `Review ${req.reviewID} updated successfully`, newReview: completeReview});
    }
    else{
      return res.status(400).send({success: false, message: "API Response: " + error.message});
    }  
})

app.delete('/reviews/:id', validateAccessToken, validateReviewAlteration, (req,res) => {
  reviews.splice(req.reviewIndex, 1);
  return res.status(200).send({success: true, message: `Review ${req.reviewID} has been deleted`});
})

export default app;
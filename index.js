const express = require('express');
const app = express();
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cookieParser = require('cookie-parser')
const uti=require('./uti');
const port =process.env.PORT ||5000;
const jwt = require('jsonwebtoken');
require('dotenv').config()

//mongodb url
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.ufscwyv.mongodb.net/?retryWrites=true&w=majority`;
//mongodb client
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });
//db collections
const userCollection = client.db('quiz-station').collection('user');
const quizCollection = client.db('quiz-station').collection('quiz');
const resultCollection = client.db('quiz-station').collection('result');


//middleware
app.use(cors());
app.use(express.json());
app.use(cookieParser());
const verifyJwt=async(req,res,next)=>{
    const email=req.headers.email;
    const filter={email};
    const result=await userCollection.findOne(filter);
    if(result==={}||!result){
        return res.send({status:"failed",message:"cant find user"});
    }
    const secret=result.secret;
    const accessToken=req.headers.accesstoken.split(" ")[1];
    try {
        const payload = jwt.verify(accessToken, secret)
        next();
      } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            return res.send({status:"Token expired", message:"Token expired user refresh token"})
          } else {
            return res.send({status:"unauthorized", message:"cant process token"});
          }
      }
};

try{
  //test server
app.get('/', (req, res) => {
  res.send('Hello Learners!')
});

//login and jwt
app.post('/login',async (req, res) => {
    // Get the request body data
    const {name,email} = req.body;

    //secret for jwt
    const secret =uti.secretCreate();

    //update secret to userDb
    const filter={email};
    const updateDoc = {
        $set: {
          secret
        },
      };
    const result = await userCollection.updateOne(filter, updateDoc);

    //getting jwt
    const {accessToken,refreshToken}=uti.jwtCreate(name,email,secret);

    if(result.modifiedCount!=1){
        return res.send({status:"failed",message: 'Cant Connect To DataBase',accessToken:null })
    }
    // Set the refresh JWT as an HTTP-only cookie
    res.cookie('refresh_token', refreshToken, { httpOnly: true })
  
    // Send the access and refresh JWTs back to the client
    res.send({ accessToken })
  });
  

//api for uploading user information in Db when registration is successful and jwt apply
app.post('/users',async (req, res) => {
    // Get the request body data
    const {name,email} = req.body;

    //secret for jwt
    const secret =uti.secretCreate();

    //getting jwt
    const {accessToken,refreshToken}=uti.jwtCreate(name,email,secret);
  
    const data={
        name,
        email,
        secret
    }

    //saving it to a database
    const result=await userCollection.insertOne(data);

    // Send a response back to the client
    if(!result.acknowledged){
        return res.send({status:"failed",message: 'Cant Upload User Info To DataBase',accessToken:null })
    }
    // Set the refresh JWT as an HTTP-only cookie
    res.cookie('refresh_token', refreshToken, { httpOnly: true })

    res.send({status:"success",message: 'User Info Uploaded To DataBase Successfully',accessToken })
  });


//getting user info
app.get('/user/info/:email',async(req, res) => {
    const email=req.params.email;
    const filter={email};
    const result=await userCollection.find(filter).toArray();
    if(!result){
      return res.status({status:false})
    }
    return res.send({user:result});
})

//get access token by using the refresh token
app.post('/refresh',async (req, res) => {
    //verifying user
    const email=req.query.email;
    const filter={email};
    const result=await userCollection.findOne(filter);
    if(result==={}||!result){
        return res.send({status:"failed",message:"cant find user"});
    }
    const secret=result.secret;

    // Get the refresh JWT from the cookie
    const refreshToken = req.cookies.refresh_token;
  
    // Verify the refresh JWT and get the payload
    const payload = jwt.verify(refreshToken, secret)
    if (!payload) {
      return res.status(401).send({ message: 'Invalid refresh token' })
    }
  
    // Create a new access JWT for the authenticated user
    const accessToken = jwt.sign({ id: payload.id, name: payload.name }, secret, { expiresIn: '15m' })
  
    // Send the new access JWT back to the client
    res.send({ accessToken })
  });

//get quiz topic
app.get('/topics',async(req, res)=>{
    const topics=await quizCollection.find({}).toArray();
    const finalTopic=topics.map(topic=>{
      return {
        id: topic.id,
        name: topic.name,
        logo:topic.logo,
        total:topic.total
      }
    });
    if(finalTopic.length==0){
      return res.send({status:false,data:[]});
    }
    res.send({status:true,data:finalTopic});
});

//get one topic's quiz 
app.get('/topics/:id',verifyJwt,async(req, res)=>{
    const id=parseInt(req.params.id);
    const quiz=await quizCollection.find({id}).toArray();
    if(quiz.length==0){
      return res.send({status:false,data:[]});
    }
    res.send({status:true,data:quiz});
});

//post result to server
app.post('/result/:email',async(req, res)=>{
    const email=req.params.email;
    const data=req.body;
    const result=await resultCollection.insertOne(data);
    res.send({status:true,result})
});

//getting results
app.get('/result/:email',async(req, res)=>{
    const email=req.params.email;
    const filter={email:email};
    const result=await resultCollection.find(filter).toArray();
    res.send({status:true, result})
});

//delete
app.delete('/user/delete',async(req, res)=>{
    const email=req.query.email;
    const filter={email};
    const result=await userCollection.deleteOne(filter);
    res.send(result);
});

//getting results individually
app.get('/IndResult/:id',async(req, res)=>{
    const id=req.params.id;
    const filter={_id:ObjectId(id)};
    const result=await resultCollection.find(filter).toArray();
    res.send({status:true, result})
});

}catch(err) {
    console.log(err);
}
//launch
app.listen(port, () => {
  console.log('Example app listening on port',port)
})

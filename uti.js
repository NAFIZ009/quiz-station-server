const jwt = require('jsonwebtoken')
const crypto = require('crypto');


const jwtCreate=(name,email,secret)=>{
      
        // Create an access JWT for the authenticated user
        const accessToken = jwt.sign({ name,email }, secret, { expiresIn: '15m' })
      
        // Create a refresh JWT for the authenticated user
        const refreshToken = jwt.sign({ email }, secret, { expiresIn: '7d' })
      
        
        return {accessToken,refreshToken};
      
};

const secretCreate=()=>{
    //random secret
    const secret = crypto.randomBytes(64).toString('hex');

    return secret;

};



module.exports={jwtCreate,secretCreate}
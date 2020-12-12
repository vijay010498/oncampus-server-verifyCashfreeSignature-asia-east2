const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

//validate token using headers
const validateFirebaseIdToken = async (req,res,next) =>{
    console.log('Checking ID');
    if((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) &&
        !(req.cookies && req.cookies._session)){
          res.status(403).send('Unauthorized');
          return;
        }
        let idToken;
        if(req.headers.authorization && req.headers.authorization.startsWith('Bearer ')){
          idToken = req.headers.authorization.split('Bearer ')[1];
        }
        else if(req.cookies){
          idToken = req.cookies._session;
        }
        else {
          res.status(403).send('Unauthorized');
          return;
        }
        try{
          const decodedIdToken = await admin.auth().verifyIdToken(idToken);
          req.user = decodedIdToken;
          next();
          return;
        }catch(error){
          res.status(403).send('Unauthorized');
          return;
        }
}

//init app
const app = express();
app.use(cors({origin:true}));

app.use(validateFirebaseIdToken);

app.get('/verifySignature',async (req,res) =>{
    let orderId = req.query.orderId;
    let orderAmount = req.query.orderAmount;
    let referenceId = req.query.referenceId;
    let txStatus = req.query.txStatus;
    let paymentMode = req.query.paymentMode;
    let txMsg = req.query.txMsg;
    let txTime = req.query.txTime;

    if(orderId === undefined || orderId === null)
        res.status(401).send("Error orderId not found");
    else if(orderAmount === undefined || orderAmount === null)
        res.status(401).send("Error orderAmount not found");
    else if(referenceId === undefined || referenceId === null)
        res.status(401).send("Error referenceId not found" );
    else if(txStatus === undefined || txStatus === null)
        res.status(401).send("Error Transaction status not found");
    else if(paymentMode === undefined || paymentMode === null)
        res.status(401).send("Error payment mode not found");
    else if(txMsg === undefined || txMsg === null)
        res.status(401).send("Error Transacion message not found");
    else if(txTime === undefined || txTime === null)
        res.status(401).send("Error Transaction Time not found");
    else{
        var data = orderId+orderAmount+referenceId+txStatus+paymentMode+txMsg+txTime;
        var secretKey = "c8717547fefcc4cc6f593b128ee22cf997f6e69b";
        var computedSignature = crypto.createHmac('SHA256',secretKey).update(data).digest('base64');
        console.log(computedSignature);
        res.send(JSON.stringify({computedSignature:computedSignature}));
    }
});
exports.verifyCashfreeSignature = functions
                                  .region('asia-east2')  
                                  .https.onRequest(app);




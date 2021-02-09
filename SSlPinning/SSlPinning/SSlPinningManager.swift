//
//  SSlPinningManager.swift
//  SSlPinning
//
//  Created by Abhimanyu Rathore on 09/02/21.
//

import Foundation
import Security
import CommonCrypto


class  SSlPinningManager:NSObject,URLSessionDelegate {
    
    static let shared = SSlPinningManager()
    
    var isCertificatePinning:Bool = false
    
    
    var hardcodedPublicKey:String = "iie1VXtL7HzAMF+/PVPR9xzT80kQxdZeJ+zduCB3uj0="
    
    
    
    let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    
    private func sha256(data : Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
    
    
    
    
    
    //MARK:- URLSessionDelegate
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge,nil)
            return
        }
        
        
        
        //extarct certificate from each api
        
        if self.isCertificatePinning {
            //compare certificates remote and local
            let certificate =  SecTrustGetCertificateAtIndex(serverTrust, 2)
            
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            
            let isSecuredServer = SecTrustEvaluateWithError(serverTrust, nil)
            
            let remoteCertiData:NSData  = SecCertificateCopyData(certificate!)
            
            
            guard let pathToCertificate = Bundle.main.path(forResource: "GlobalSign", ofType: "cer") else{
                fatalError("no local path found")
            }
            
            let localCertiData = NSData(contentsOfFile: pathToCertificate)
            if isSecuredServer && remoteCertiData.isEqual(to:localCertiData! as Data)  {
                print("Certificate   Pinning Completed Successfully")
                
                completionHandler(.useCredential, URLCredential.init(trust: serverTrust))
            }else{
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        }else{
            //compare Keys
            if let certificate =  SecTrustGetCertificateAtIndex(serverTrust, 2) {
                
                let serverPublicKey = SecCertificateCopyKey(certificate)
                let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil)
                let data:Data = serverPublicKeyData as! Data
                let serverHashKey = sha256(data: data)
                if serverHashKey == self.hardcodedPublicKey {
                    print("public key Pinning Completed Successfully")
                    completionHandler(.useCredential, URLCredential.init(trust: serverTrust))
                }else{
                    completionHandler(.cancelAuthenticationChallenge,nil)

                }
            }
        }
    }
    
    func callAnyApi(urlString:String,isCertificatePinning:Bool,response:@escaping ((String)-> ())){
        
        let sessionObj = URLSession(configuration: .ephemeral,delegate: self,delegateQueue: nil)
        self.isCertificatePinning = isCertificatePinning
        var result:String =  ""
        
        guard let url = URL.init(string: urlString) else {
            fatalError("please add valid url first")
        }
        
        let task = sessionObj.dataTask(with: url) { (data, res, error) in
            
            if  error?.localizedDescription == "cancelled" {
                response("ssl Pinning failed")
            }
            if let data = data {
                let str = String(decoding: data, as: UTF8.self)
                print(str)
                if self.isCertificatePinning {
                    response("ssl Pinning successful with Certificate Pinning")
                }else{
                    response("ssl Pinning successful with Public Key  Pinning")
                    
                }
            }
            
        }
        task.resume()
    }

    
}

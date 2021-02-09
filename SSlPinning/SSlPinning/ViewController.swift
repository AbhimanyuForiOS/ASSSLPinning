//
//  ViewController.swift
//  SSlPinning
//
//  Created by Abhimanyu Rathore on 09/02/21.
//

import UIKit

//https://www.google.com
class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        SSlPinningManager.shared.callAnyApi(urlString: "https://www.google.com", isCertificatePinning: false) { (response) in
            print(response)
        }
        
        // Do any additional setup after loading the view.
    }


}


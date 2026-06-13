// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x06f1dfb8769132a0921310dbb9b13fafe541eb903bb2c3996290e09d5b1f5c98), uint256(0x28e6016aa5a588a8fa68bdd768e81d2e582be6299fd8b82fd2ded06582ab65a4));
        vk.beta = Pairing.G2Point([uint256(0x146b934ccbac7cdac29221e7baf37545cda9bbb9ef8da7115df7671062240ce0), uint256(0x27d15d332ef6a5838e96f31a721912fb696ed752cda6f2551d87564378178e9c)], [uint256(0x069374f62364fd9d26dedaa1a92a975fbe29234a2c3ba91a6ba9b69735e32e17), uint256(0x1e148c92fd148b16db8e677aca9df264c6ea41340eb0b45605c4692f7612aadf)]);
        vk.gamma = Pairing.G2Point([uint256(0x2705b7d59d9745fbca8ee0981dc4651324ced951d286b001fab5d2ed21593aa6), uint256(0x102fc75feae6d52728620344ba7e85fc335bcda86f3d85b8f6e0cb899ab86705)], [uint256(0x13bb51f4f112333f2eaa5d92abf3f7a3330664a69b6774269e894d845b26e13e), uint256(0x05de8f59d0b8bffd969e070ce0b55ba4783beea68528818a035406f106efcda1)]);
        vk.delta = Pairing.G2Point([uint256(0x1691239b92feb7a6c50b7a9be8b7aef2c404a71452b84885a2b28611a05e4148), uint256(0x061750d28fa10e0f3743817606deb8c9baa65c128db60e50515a532b5a126b1f)], [uint256(0x0e68a3c2e38280d0741df7b88adfa231016fa6d3de774d16e00d059a3c8d86dd), uint256(0x0462e06fb9665693b71340c6c62e5dfb0e6c6c3c3e862d8124d60750f035cda5)]);
        vk.gamma_abc = new Pairing.G1Point[](10);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x234173c9e3795962dec94ef1cc7f50c33d91db4fc005d6db6c20fb3b90315ab7), uint256(0x17123ee61dcc590f7d7c54c5e7b7ad445560ed57d1cef3637283c77574142f65));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x273060cebd4448d9419b67fa51bdc155390f8294b2652459243162c6726c4a5a), uint256(0x00c1a6668db7e2f5298280ee37b72548a24745fff4869232059855be13165dc4));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x20380233a19620fa3c4c475876af921160d9d0f87eb1483ac2756a9f980eddb4), uint256(0x157a7323a926816a3c5c6ea2f909b8bcde76b5eea829f5bb68c1da4bfe520223));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1d28e2a2b545604fe2b7c5e24eefeac84c244b991b1c747f2e28d62117603d6a), uint256(0x0f57426aa934e0b2b079b1471bdbf64f744a556f8e04a54d1b30c13fa494adbe));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x14e8615a0126dac9a9f2b2bc84a8de7a815f1ae22c8037340864afd797dc381d), uint256(0x2c3545baea1820d4c05e3c33e536d8d5fc457958577952fc27de0db2e9b44595));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x10ad72dbc4927cf83df6d80de67a75408aee8e4b52d2276f5e9401c5ac26cddd), uint256(0x1ef2700a0e6d1677589501686cb8e52781a26c0bedc8b87aeaa73f365c5fdd1d));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x070aa79105c4fb50f416c92e31473c3016c1f65ed32fccb3bf04cbe6b5fc1647), uint256(0x0a67a4d21be56f53c55ad9a64b9a787c9e772d13287eae3f620fd8c50ef09ba3));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x185a61d0c29a7e572d2bc7931a58f65841538e6d9cc182a67d8cb993153d4314), uint256(0x1ccb1356bf5596397740690b201b72a225dd275c07b47c0032f03daecf973e3a));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2ce3e6c8c0ced0dc7cef0ddecd552bf81dc58a0f67985f2c68cc4e7868cfd6d4), uint256(0x24cc293bba57d8464370ebab80d100489bb16ea6e0a8300bdcb53a63a47112ae));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2a6709273d78352769e33228083a235870a08c5053d01b85ea9f294b0bc28dc8), uint256(0x2603d04fafbf4e5e1b311e0c31e0370b55a7527aea1a086c8e400b2abd2259fa));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[9] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](9);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}

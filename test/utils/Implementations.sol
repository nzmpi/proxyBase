//SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract Implementation {
    bool flag;

    function toggle() external {
        flag = !flag;
    }

    function getFlag() external view returns (bool) {
        return flag;
    }
}

contract Implementation2 is Implementation {
    function initialize(bool _flag) external {
        flag = _flag;
    }

    function getReverseFlag() external view returns (bool) {
        return !flag;
    }
}

contract Implementation3 is Implementation2 {
    bytes data;

    function initialize(bytes calldata initData) external {
        data = initData;
    }

    function getData() external view returns (bytes memory) {
        return data;
    }
}

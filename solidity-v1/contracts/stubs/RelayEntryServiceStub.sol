pragma solidity 0.5.17;

import "../KeepRandomBeaconOperator.sol";
import "../KeepRandomBeaconServiceImplV1.sol";

contract RelayEntryServiceStub {
    function sign(
        KeepRandomBeaconOperator operator,
        uint256 requestId,
        bytes memory previousEntry
    ) public payable {
        operator.sign.value(msg.value)(requestId, previousEntry);
    }

    function entryCreated(
        uint256,
        bytes memory,
        address payable
    ) public {
        revert("entryCreated failed");
    }

    function callServiceEntryCreated(
        KeepRandomBeaconServiceImplV1 service,
        uint256 requestId,
        bytes memory entry,
        address payable submitter
    ) public {
        service.entryCreated(requestId, entry, submitter);
    }

    function callServiceExecuteCallback(
        KeepRandomBeaconServiceImplV1 service,
        uint256 requestId,
        uint256 entry
    ) public {
        service.executeCallback(requestId, entry);
    }

    function fundRequestSubsidyFeePool() public payable {}

    function fundDkgFeePool() public payable {}

    function callbackSurplusRecipient(uint256)
        public
        view
        returns (address payable)
    {
        return address(uint160(address(this)));
    }
}

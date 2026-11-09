// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ThreatRegistry} from "../src/ThreatRegistry.sol";

contract ThreatRegistryTest is Test {
    ThreatRegistry reg;

    address owner = address(this);
    address validator = makeAddr("validator");
    address relayer = makeAddr("relayer");
    address stranger = makeAddr("stranger");

    bytes32 constant H1 = keccak256("report-1");
    bytes32 constant H2 = keccak256("report-2");
    bytes32 constant H3 = keccak256("report-3");
    bytes32 constant REASON = keccak256("reason");

    // mirror events for expectEmit
    event ReportSubmitted(uint256 indexed id, bytes32 indexed reportHash, bytes32 parentHash, address indexed reporter);
    event ReportSuperseded(uint256 indexed parentId, uint256 indexed childId);
    event ReportDisputed(uint256 indexed id, address indexed disputer, bytes32 reasonHash);
    event StatusChanged(uint256 indexed id, ThreatRegistry.Status from, ThreatRegistry.Status to, address indexed by);
    event ValidatorAdded(address indexed account);
    event ValidatorRemoved(address indexed account);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        reg = new ThreatRegistry();
        reg.addValidator(validator);
    }

    function _submit(bytes32 h) internal returns (uint256) {
        vm.prank(relayer);
        return reg.submitReport(h, bytes32(0));
    }

    function _status(uint256 id) internal view returns (ThreatRegistry.Status) {
        return reg.getReport(id).status;
    }

    // ---------- constructor ----------

    function test_Constructor_SetsOwnerAndEmits() public {
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(address(0), address(this));
        ThreatRegistry r = new ThreatRegistry();
        assertEq(r.owner(), address(this));
        assertEq(r.reportCount(), 0);
        assertFalse(r.isValidator(address(this)));
    }

    // ---------- submitReport ----------

    function test_Submit_StoresReport() public {
        vm.warp(1_700_000_000);
        vm.expectEmit(true, true, true, true);
        emit ReportSubmitted(1, H1, bytes32(0), relayer);
        uint256 id = _submit(H1);

        assertEq(id, 1);
        ThreatRegistry.Report memory r = reg.getReport(id);
        assertEq(r.reportHash, H1);
        assertEq(r.parentHash, bytes32(0));
        assertEq(r.reporter, relayer);
        assertEq(r.createdAt, 1_700_000_000);
        assertEq(uint8(r.status), uint8(ThreatRegistry.Status.Submitted));
        assertEq(reg.idOfHash(H1), 1);
        assertEq(reg.reportCount(), 1);
    }

    function test_Submit_SequentialIds() public {
        assertEq(_submit(H1), 1);
        assertEq(_submit(H2), 2);
        assertEq(reg.reportCount(), 2);
    }

    function test_Submit_WithParent_SupersedesParent() public {
        uint256 p = _submit(H1);
        vm.expectEmit(true, true, true, true);
        emit ReportSubmitted(2, H2, H1, relayer);
        vm.expectEmit(true, true, false, true);
        emit StatusChanged(p, ThreatRegistry.Status.Submitted, ThreatRegistry.Status.Superseded, relayer);
        vm.expectEmit(true, true, false, false);
        emit ReportSuperseded(p, 2);
        vm.prank(relayer);
        uint256 c = reg.submitReport(H2, H1);

        assertEq(uint8(_status(p)), uint8(ThreatRegistry.Status.Superseded));
        assertEq(uint8(_status(c)), uint8(ThreatRegistry.Status.Submitted));
        assertEq(reg.getReport(c).parentHash, H1);
    }

    function test_Submit_SupersedeChain() public {
        _submit(H1);
        vm.startPrank(relayer);
        reg.submitReport(H2, H1);
        reg.submitReport(H3, H2);
        vm.stopPrank();
        assertEq(uint8(_status(1)), uint8(ThreatRegistry.Status.Superseded));
        assertEq(uint8(_status(2)), uint8(ThreatRegistry.Status.Superseded));
        assertEq(uint8(_status(3)), uint8(ThreatRegistry.Status.Submitted));
    }

    function test_Submit_CanSupersedeValidatedOrDisputedParent() public {
        uint256 a = _submit(H1);
        vm.prank(validator);
        reg.setStatus(a, ThreatRegistry.Status.Validated);
        vm.prank(relayer);
        reg.submitReport(H2, H1);
        assertEq(uint8(_status(a)), uint8(ThreatRegistry.Status.Superseded));

        uint256 b = _submit(H3);
        reg.disputeReport(b, REASON);
        vm.prank(relayer);
        reg.submitReport(keccak256("report-4"), H3);
        assertEq(uint8(_status(b)), uint8(ThreatRegistry.Status.Superseded));
    }

    function test_RevertWhen_Submit_ZeroHash() public {
        vm.expectRevert(ThreatRegistry.ZeroHash.selector);
        reg.submitReport(bytes32(0), bytes32(0));
    }

    function test_RevertWhen_Submit_Duplicate() public {
        _submit(H1);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.DuplicateHash.selector, H1));
        vm.prank(stranger);
        reg.submitReport(H1, bytes32(0));
    }

    function test_RevertWhen_Submit_SelfParentUnregistered() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ParentNotFound.selector, H1));
        reg.submitReport(H1, H1);
    }

    function test_RevertWhen_Submit_ParentNotFound() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ParentNotFound.selector, H1));
        reg.submitReport(H2, H1);
    }

    function test_RevertWhen_Submit_NotParentOwner() public {
        uint256 p = _submit(H1);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.NotParentOwner.selector, p));
        vm.prank(stranger);
        reg.submitReport(H2, H1);
    }

    function test_RevertWhen_Submit_ParentAlreadySuperseded() public {
        uint256 p = _submit(H1);
        vm.startPrank(relayer);
        reg.submitReport(H2, H1);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ParentAlreadySuperseded.selector, p));
        reg.submitReport(H3, H1);
        vm.stopPrank();
    }

    function test_RevertWhen_Submit_ParentRejected() public {
        uint256 p = _submit(H1);
        vm.prank(validator);
        reg.setStatus(p, ThreatRegistry.Status.Rejected);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ParentRejected.selector, p));
        vm.prank(relayer);
        reg.submitReport(H2, H1);
        // rejection stays visible and the new hash was not registered
        assertEq(uint8(_status(p)), uint8(ThreatRegistry.Status.Rejected));
        assertEq(reg.idOfHash(H2), 0);
    }

    // ---------- disputeReport ----------

    function test_Dispute_FromSubmitted() public {
        uint256 id = _submit(H1);
        vm.expectEmit(true, true, false, true);
        emit ReportDisputed(id, stranger, REASON);
        vm.expectEmit(true, true, false, true);
        emit StatusChanged(id, ThreatRegistry.Status.Submitted, ThreatRegistry.Status.Disputed, stranger);
        vm.prank(stranger);
        reg.disputeReport(id, REASON);
        assertEq(uint8(_status(id)), uint8(ThreatRegistry.Status.Disputed));
    }

    function test_Dispute_FromValidated() public {
        uint256 id = _submit(H1);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        vm.prank(stranger);
        reg.disputeReport(id, REASON);
        assertEq(uint8(_status(id)), uint8(ThreatRegistry.Status.Disputed));
    }

    function test_RevertWhen_Dispute_NotFound() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ReportNotFound.selector, 1));
        reg.disputeReport(1, REASON);
    }

    function test_RevertWhen_Dispute_ZeroReason() public {
        uint256 id = _submit(H1);
        vm.expectRevert(ThreatRegistry.ZeroHash.selector);
        reg.disputeReport(id, bytes32(0));
    }

    function test_RevertWhen_Dispute_AlreadyDisputed() public {
        uint256 id = _submit(H1);
        reg.disputeReport(id, REASON);
        vm.expectRevert(
            abi.encodeWithSelector(
                ThreatRegistry.InvalidTransition.selector,
                ThreatRegistry.Status.Disputed,
                ThreatRegistry.Status.Disputed
            )
        );
        reg.disputeReport(id, REASON);
    }

    function test_RevertWhen_Dispute_Rejected() public {
        uint256 id = _submit(H1);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Rejected);
        vm.expectRevert(
            abi.encodeWithSelector(
                ThreatRegistry.InvalidTransition.selector,
                ThreatRegistry.Status.Rejected,
                ThreatRegistry.Status.Disputed
            )
        );
        reg.disputeReport(id, REASON);
    }

    function test_RevertWhen_Dispute_Superseded() public {
        uint256 id = _submit(H1);
        vm.prank(relayer);
        reg.submitReport(H2, H1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ThreatRegistry.InvalidTransition.selector,
                ThreatRegistry.Status.Superseded,
                ThreatRegistry.Status.Disputed
            )
        );
        reg.disputeReport(id, REASON);
    }

    // ---------- setStatus ----------

    function test_SetStatus_SubmittedToValidated() public {
        uint256 id = _submit(H1);
        vm.expectEmit(true, true, false, true);
        emit StatusChanged(id, ThreatRegistry.Status.Submitted, ThreatRegistry.Status.Validated, validator);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        assertEq(uint8(_status(id)), uint8(ThreatRegistry.Status.Validated));
    }

    function test_SetStatus_SubmittedToRejected() public {
        uint256 id = _submit(H1);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Rejected);
        assertEq(uint8(_status(id)), uint8(ThreatRegistry.Status.Rejected));
    }

    function test_SetStatus_DisputedToValidatedOrRejected() public {
        uint256 a = _submit(H1);
        uint256 b = _submit(H2);
        reg.disputeReport(a, REASON);
        reg.disputeReport(b, REASON);
        vm.startPrank(validator);
        reg.setStatus(a, ThreatRegistry.Status.Validated);
        reg.setStatus(b, ThreatRegistry.Status.Rejected);
        vm.stopPrank();
        assertEq(uint8(_status(a)), uint8(ThreatRegistry.Status.Validated));
        assertEq(uint8(_status(b)), uint8(ThreatRegistry.Status.Rejected));
    }

    function test_SetStatus_ValidatedToRejected() public {
        uint256 id = _submit(H1);
        vm.startPrank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        reg.setStatus(id, ThreatRegistry.Status.Rejected);
        vm.stopPrank();
        assertEq(uint8(_status(id)), uint8(ThreatRegistry.Status.Rejected));
    }

    function test_RevertWhen_SetStatus_NotValidator() public {
        uint256 id = _submit(H1);
        vm.expectRevert(ThreatRegistry.NotValidator.selector);
        vm.prank(relayer); // the relayer has no validator role
        reg.setStatus(id, ThreatRegistry.Status.Validated);

        vm.expectRevert(ThreatRegistry.NotValidator.selector);
        reg.setStatus(id, ThreatRegistry.Status.Validated); // owner is not automatically a validator
    }

    function test_RevertWhen_SetStatus_InvalidTarget() public {
        uint256 id = _submit(H1);
        ThreatRegistry.Status[3] memory bad =
            [ThreatRegistry.Status.Submitted, ThreatRegistry.Status.Disputed, ThreatRegistry.Status.Superseded];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.InvalidStatus.selector, bad[i]));
            vm.prank(validator);
            reg.setStatus(id, bad[i]);
        }
    }

    function test_RevertWhen_SetStatus_NotFound() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ReportNotFound.selector, 7));
        vm.prank(validator);
        reg.setStatus(7, ThreatRegistry.Status.Validated);
    }

    function test_RevertWhen_SetStatus_SameStatus() public {
        uint256 id = _submit(H1);
        vm.startPrank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        vm.expectRevert(
            abi.encodeWithSelector(
                ThreatRegistry.InvalidTransition.selector,
                ThreatRegistry.Status.Validated,
                ThreatRegistry.Status.Validated
            )
        );
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        vm.stopPrank();
    }

    function test_RevertWhen_SetStatus_FromRejected() public {
        uint256 id = _submit(H1);
        vm.startPrank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Rejected);
        vm.expectRevert(
            abi.encodeWithSelector(
                ThreatRegistry.InvalidTransition.selector,
                ThreatRegistry.Status.Rejected,
                ThreatRegistry.Status.Validated
            )
        );
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        vm.stopPrank();
    }

    function test_RevertWhen_SetStatus_FromSuperseded() public {
        uint256 id = _submit(H1);
        vm.prank(relayer);
        reg.submitReport(H2, H1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ThreatRegistry.InvalidTransition.selector,
                ThreatRegistry.Status.Superseded,
                ThreatRegistry.Status.Validated
            )
        );
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
    }

    // ---------- getReport / idOfHash ----------

    function test_RevertWhen_GetReport_IdZero() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ReportNotFound.selector, 0));
        reg.getReport(0);
    }

    function test_RevertWhen_GetReport_OutOfRange() public {
        _submit(H1);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ReportNotFound.selector, 2));
        reg.getReport(2);
    }

    function test_IdOfHash_UnknownIsZero() public view {
        assertEq(reg.idOfHash(H1), 0);
    }

    // ---------- validators ----------

    function test_AddValidator() public {
        vm.expectEmit(true, false, false, false);
        emit ValidatorAdded(stranger);
        reg.addValidator(stranger);
        assertTrue(reg.isValidator(stranger));
    }

    function test_RemoveValidator() public {
        vm.expectEmit(true, false, false, false);
        emit ValidatorRemoved(validator);
        reg.removeValidator(validator);
        assertFalse(reg.isValidator(validator));

        uint256 id = _submit(H1);
        vm.expectRevert(ThreatRegistry.NotValidator.selector);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
    }

    function test_RevertWhen_AddValidator_NotOwner() public {
        vm.expectRevert(ThreatRegistry.NotOwner.selector);
        vm.prank(validator);
        reg.addValidator(stranger);
    }

    function test_RevertWhen_AddValidator_ZeroAddress() public {
        vm.expectRevert(ThreatRegistry.ZeroAddress.selector);
        reg.addValidator(address(0));
    }

    function test_RevertWhen_AddValidator_Already() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.AlreadyValidator.selector, validator));
        reg.addValidator(validator);
    }

    function test_RevertWhen_RemoveValidator_NotOwner() public {
        vm.expectRevert(ThreatRegistry.NotOwner.selector);
        vm.prank(stranger);
        reg.removeValidator(validator);
    }

    function test_RevertWhen_RemoveValidator_NotAValidator() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.NotAValidator.selector, stranger));
        reg.removeValidator(stranger);
    }

    // ---------- ownership ----------

    function test_TransferOwnership() public {
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, stranger);
        reg.transferOwnership(stranger);
        assertEq(reg.owner(), stranger);

        vm.expectRevert(ThreatRegistry.NotOwner.selector);
        reg.addValidator(relayer); // old owner lost rights
        vm.prank(stranger);
        reg.addValidator(relayer);
        assertTrue(reg.isValidator(relayer));
    }

    function test_RevertWhen_TransferOwnership_NotOwner() public {
        vm.expectRevert(ThreatRegistry.NotOwner.selector);
        vm.prank(stranger);
        reg.transferOwnership(stranger);
    }

    function test_RevertWhen_TransferOwnership_ZeroAddress() public {
        vm.expectRevert(ThreatRegistry.ZeroAddress.selector);
        reg.transferOwnership(address(0));
    }

    // ---------- fuzz ----------

    function testFuzz_SubmitGetReportRoundTrip(bytes32 h, address reporter, uint64 ts) public {
        vm.assume(h != bytes32(0));
        vm.warp(ts);
        vm.prank(reporter);
        uint256 id = reg.submitReport(h, bytes32(0));

        ThreatRegistry.Report memory r = reg.getReport(id);
        assertEq(r.reportHash, h);
        assertEq(r.parentHash, bytes32(0));
        assertEq(r.reporter, reporter);
        assertEq(r.createdAt, ts);
        assertEq(uint8(r.status), uint8(ThreatRegistry.Status.Submitted));
        assertEq(reg.idOfHash(h), id);
    }

    function testFuzz_SubmitWithParentRoundTrip(bytes32 parent, bytes32 child, address reporter, uint64 ts) public {
        vm.assume(parent != bytes32(0) && child != bytes32(0) && parent != child);
        vm.startPrank(reporter);
        uint256 p = reg.submitReport(parent, bytes32(0));
        vm.warp(ts);
        uint256 c = reg.submitReport(child, parent);
        vm.stopPrank();

        ThreatRegistry.Report memory r = reg.getReport(c);
        assertEq(r.reportHash, child);
        assertEq(r.parentHash, parent);
        assertEq(r.reporter, reporter);
        assertEq(r.createdAt, ts);
        assertEq(uint8(reg.getReport(p).status), uint8(ThreatRegistry.Status.Superseded));
    }

    function testFuzz_DuplicateAlwaysReverts(bytes32 h, address a, address b) public {
        vm.assume(h != bytes32(0));
        vm.prank(a);
        reg.submitReport(h, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.DuplicateHash.selector, h));
        vm.prank(b);
        reg.submitReport(h, bytes32(0));
    }
}

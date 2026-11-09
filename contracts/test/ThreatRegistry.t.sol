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
    address otherReporter = makeAddr("otherReporter");

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
    event ReporterAdded(address indexed account);
    event ReporterRemoved(address indexed account);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        reg = new ThreatRegistry();
        reg.addValidator(validator);
        reg.addReporter(relayer);
        reg.addReporter(otherReporter);
    }

    function _allowReporter(address a) internal {
        if (a != address(0) && !reg.isReporter(a)) reg.addReporter(a);
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
        assertFalse(r.isReporter(address(this)));
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
        vm.prank(relayer);
        reg.submitReport(bytes32(0), bytes32(0));
    }

    function test_RevertWhen_Submit_Duplicate() public {
        _submit(H1);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.DuplicateHash.selector, H1));
        vm.prank(otherReporter);
        reg.submitReport(H1, bytes32(0));
    }

    function test_RevertWhen_Submit_SelfParentUnregistered() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ParentNotFound.selector, H1));
        vm.prank(relayer);
        reg.submitReport(H1, H1);
    }

    function test_RevertWhen_Submit_ParentNotFound() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ParentNotFound.selector, H1));
        vm.prank(relayer);
        reg.submitReport(H2, H1);
    }

    function test_RevertWhen_Submit_NotParentOwner() public {
        uint256 p = _submit(H1);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.NotParentOwner.selector, p));
        vm.prank(otherReporter);
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

    /// Open submission let anyone register the hash of a report.json they wrote (forged MATCH), or copy our pending
    /// hash from the mempool and register it first (front-running). Only authorised reporters may submit.
    function test_RevertWhen_Submit_NotReporter() public {
        vm.expectRevert(ThreatRegistry.NotReporter.selector);
        vm.prank(stranger);
        reg.submitReport(H1, bytes32(0));

        vm.expectRevert(ThreatRegistry.NotReporter.selector);
        reg.submitReport(H1, bytes32(0)); // the owner is not automatically a reporter

        vm.expectRevert(ThreatRegistry.NotReporter.selector);
        vm.prank(validator);
        reg.submitReport(H1, bytes32(0));
        assertEq(reg.idOfHash(H1), 0);
    }

    function test_FrontRunner_CannotClaimPendingHash() public {
        vm.prank(stranger); // copies H1 from the relayer's pending tx and tries to land first
        vm.expectRevert(ThreatRegistry.NotReporter.selector);
        reg.submitReport(H1, bytes32(0));
        assertEq(_submit(H1), 1);
        assertEq(reg.getReport(1).reporter, relayer);
    }

    // ---------- reporters ----------

    function test_AddReporter() public {
        vm.expectEmit(true, false, false, false);
        emit ReporterAdded(stranger);
        reg.addReporter(stranger);
        assertTrue(reg.isReporter(stranger));
        vm.prank(stranger);
        assertEq(reg.submitReport(H1, bytes32(0)), 1);
    }

    function test_RemoveReporter_KeepsExistingReports() public {
        uint256 id = _submit(H1);
        vm.expectEmit(true, false, false, false);
        emit ReporterRemoved(relayer);
        reg.removeReporter(relayer);
        assertFalse(reg.isReporter(relayer));

        vm.expectRevert(ThreatRegistry.NotReporter.selector);
        vm.prank(relayer);
        reg.submitReport(H2, bytes32(0));

        ThreatRegistry.Report memory r = reg.getReport(id);
        assertEq(r.reporter, relayer);
        assertEq(uint8(r.status), uint8(ThreatRegistry.Status.Submitted));
    }

    function test_RevertWhen_AddReporter_NotOwner() public {
        vm.expectRevert(ThreatRegistry.NotOwner.selector);
        vm.prank(relayer); // a reporter cannot add more reporters
        reg.addReporter(stranger);
    }

    function test_RevertWhen_AddReporter_ZeroAddress() public {
        vm.expectRevert(ThreatRegistry.ZeroAddress.selector);
        reg.addReporter(address(0));
    }

    function test_RevertWhen_AddReporter_Already() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.AlreadyReporter.selector, relayer));
        reg.addReporter(relayer);
    }

    function test_RevertWhen_RemoveReporter_NotOwner() public {
        vm.expectRevert(ThreatRegistry.NotOwner.selector);
        vm.prank(stranger);
        reg.removeReporter(relayer);
    }

    function test_RevertWhen_RemoveReporter_NotAReporter() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.NotAReporter.selector, stranger));
        reg.removeReporter(stranger);
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
        vm.assume(h != bytes32(0) && reporter != address(0));
        _allowReporter(reporter);
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
        vm.assume(parent != bytes32(0) && child != bytes32(0) && parent != child && reporter != address(0));
        _allowReporter(reporter);
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
        vm.assume(h != bytes32(0) && a != address(0) && b != address(0));
        _allowReporter(a);
        _allowReporter(b);
        vm.prank(a);
        reg.submitReport(h, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.DuplicateHash.selector, h));
        vm.prank(b);
        reg.submitReport(h, bytes32(0));
    }

    // ---------- v2: dispute bond ----------

    event DisputeBondChanged(uint256 previous, uint256 current);
    event DisputeResolved(uint256 indexed id, address indexed disputer, bool upheld, uint256 bond);
    event Withdrawal(address indexed account, uint256 amount);

    uint96 constant BOND = 0.001 ether;

    function _bonded() internal returns (uint256 id) {
        reg.setDisputeBond(BOND);
        id = _submit(H1);
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        reg.disputeReport{value: BOND}(id, REASON);
    }

    function test_SetDisputeBond() public {
        vm.expectEmit(false, false, false, true);
        emit DisputeBondChanged(0, BOND);
        reg.setDisputeBond(BOND);
        assertEq(reg.disputeBond(), BOND);
    }

    function test_RevertWhen_SetDisputeBond_NotOwner() public {
        vm.expectRevert(ThreatRegistry.NotOwner.selector);
        vm.prank(stranger);
        reg.setDisputeBond(BOND);
    }

    function test_Dispute_HoldsBond() public {
        uint256 id = _bonded();
        ThreatRegistry.Dispute memory d = reg.getDispute(id);
        assertEq(d.disputer, stranger);
        assertEq(d.bond, BOND);
        assertEq(address(reg).balance, BOND);
    }

    function test_RevertWhen_Dispute_BondMissing() public {
        reg.setDisputeBond(BOND);
        uint256 id = _submit(H1);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.WrongBond.selector, 0, BOND));
        vm.prank(stranger);
        reg.disputeReport(id, REASON);
    }

    function test_RevertWhen_Dispute_Overpaid() public {
        reg.setDisputeBond(BOND);
        uint256 id = _submit(H1);
        vm.deal(stranger, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.WrongBond.selector, uint256(BOND) + 1, BOND));
        vm.prank(stranger);
        reg.disputeReport{value: uint256(BOND) + 1}(id, REASON);
    }

    function test_RevertWhen_Dispute_ValueWithZeroBond() public {
        uint256 id = _submit(H1);
        vm.deal(stranger, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.WrongBond.selector, 1, 0));
        vm.prank(stranger);
        reg.disputeReport{value: 1}(id, REASON);
    }

    function test_Resolve_Upheld_RefundsDisputer() public {
        uint256 id = _bonded();
        vm.expectEmit(true, true, false, true);
        emit DisputeResolved(id, stranger, true, BOND);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Rejected);
        assertEq(reg.pendingWithdrawal(stranger), BOND);
        assertEq(reg.getDispute(id).disputer, address(0));

        uint256 before = stranger.balance;
        vm.expectEmit(true, false, false, true);
        emit Withdrawal(stranger, BOND);
        vm.prank(stranger);
        reg.withdraw();
        assertEq(stranger.balance, before + BOND);
        assertEq(reg.pendingWithdrawal(stranger), 0);
        assertEq(address(reg).balance, 0);
    }

    function test_Resolve_Failed_ForfeitsToOwner() public {
        uint256 id = _bonded();
        vm.expectEmit(true, true, false, true);
        emit DisputeResolved(id, stranger, false, BOND);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        assertEq(reg.pendingWithdrawal(owner), BOND);
        assertEq(reg.pendingWithdrawal(stranger), 0);
    }

    function test_Validate_WithoutDispute_MovesNoFunds() public {
        uint256 id = _submit(H1);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        assertEq(reg.pendingWithdrawal(owner), 0);
    }

    function test_Supersede_Disputed_RefundsDisputer() public {
        uint256 id = _bonded();
        vm.expectEmit(true, true, false, true);
        emit DisputeResolved(id, stranger, true, BOND);
        vm.prank(relayer);
        reg.submitReport(H2, H1);
        assertEq(uint8(_status(id)), uint8(ThreatRegistry.Status.Superseded));
        assertEq(reg.pendingWithdrawal(stranger), BOND);
    }

    function test_Redispute_AfterValidation_CanBeBondedAgain() public {
        uint256 id = _bonded();
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Validated);
        vm.prank(stranger);
        reg.disputeReport{value: BOND}(id, REASON);
        assertEq(reg.getDispute(id).bond, BOND);
        assertEq(address(reg).balance, 2 * uint256(BOND));
    }

    function test_RevertWhen_Withdraw_Nothing() public {
        vm.expectRevert(ThreatRegistry.NothingToWithdraw.selector);
        vm.prank(stranger);
        reg.withdraw();
    }

    function test_RevertWhen_Withdraw_TransferFails() public {
        RejectsEther disputer = new RejectsEther(reg);
        reg.setDisputeBond(BOND);
        uint256 id = _submit(H1);
        vm.deal(address(disputer), 1 ether);
        disputer.dispute{value: BOND}(id, REASON);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Rejected);
        vm.expectRevert(ThreatRegistry.TransferFailed.selector);
        disputer.withdraw();
        assertEq(reg.pendingWithdrawal(address(disputer)), BOND); // reverted, so the credit is kept
    }

    function test_Withdraw_ReentrancyGetsNothingExtra() public {
        Reenterer attacker = new Reenterer(reg);
        reg.setDisputeBond(BOND);
        uint256 id = _submit(H1);
        vm.deal(address(attacker), 1 ether);
        attacker.dispute{value: BOND}(id, REASON);
        vm.prank(validator);
        reg.setStatus(id, ThreatRegistry.Status.Rejected);
        attacker.withdraw();
        // the bond came from this test (msg.value), so the attacker holds its 1 ether plus exactly one bond
        assertEq(address(attacker).balance, 1 ether + uint256(BOND));
        assertEq(reg.pendingWithdrawal(address(attacker)), 0);
        assertEq(address(reg).balance, 0);
    }

    function test_RevertWhen_GetDispute_NotFound() public {
        vm.expectRevert(abi.encodeWithSelector(ThreatRegistry.ReportNotFound.selector, 9));
        reg.getDispute(9);
    }
}

contract RejectsEther {
    ThreatRegistry reg;

    constructor(ThreatRegistry r) {
        reg = r;
    }

    function dispute(uint256 id, bytes32 reason) external payable {
        reg.disputeReport{value: msg.value}(id, reason);
    }

    function withdraw() external {
        reg.withdraw();
    }
}

contract Reenterer {
    ThreatRegistry reg;
    bool entered;

    constructor(ThreatRegistry r) {
        reg = r;
    }

    function dispute(uint256 id, bytes32 reason) external payable {
        reg.disputeReport{value: msg.value}(id, reason);
    }

    function withdraw() external {
        reg.withdraw();
    }

    receive() external payable {
        if (!entered) {
            entered = true;
            try reg.withdraw() {} catch {} // balance already zeroed: reverts NothingToWithdraw
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ThreatRegistry
/// @notice Append-only registry of CyberMatrix threat-report commitments.
/// @dev Only hashes, status, timestamps and the reporter address are stored. Raw report content stays off-chain.
///      No upgradability. Report ids start at 1; id 0 means "not registered".
///      v2: a dispute costs a bond (`disputeBond`), so knocking a Validated report to Disputed is no longer free.
///      A validator's ruling settles it: Rejected (dispute upheld) returns the bond to the disputer; Validated
///      (dispute failed) forfeits it to the owner. A reporter's revision (supersede) also returns it. Payouts are
///      pull-based: the only external call is `withdraw`, which zeroes the balance before sending.
///      v3: only reporters the owner authorised may submit. Open submission let anyone register the hash of a
///      report.json they wrote (a forged MATCH) or copy a pending hash from the mempool and register it first.
contract ThreatRegistry {
    enum Status {
        Submitted,
        Disputed,
        Validated,
        Rejected,
        Superseded
    }

    struct Report {
        bytes32 reportHash;
        bytes32 parentHash;
        address reporter;
        uint64 createdAt;
        Status status;
    }

    // ---------- errors ----------
    error NotOwner();
    error NotValidator();
    error NotReporter();
    error ZeroAddress();
    error ZeroHash();
    error DuplicateHash(bytes32 reportHash);
    error ParentNotFound(bytes32 parentHash);
    error NotParentOwner(uint256 parentId);
    error ParentAlreadySuperseded(uint256 parentId);
    error ParentRejected(uint256 parentId);
    error ReportNotFound(uint256 id);
    error InvalidStatus(Status status);
    error InvalidTransition(Status from, Status to);
    error AlreadyValidator(address account);
    error NotAValidator(address account);
    error AlreadyReporter(address account);
    error NotAReporter(address account);
    error WrongBond(uint256 sent, uint256 required);
    error NothingToWithdraw();
    error TransferFailed();

    // ---------- events ----------
    event ReportSubmitted(uint256 indexed id, bytes32 indexed reportHash, bytes32 parentHash, address indexed reporter);
    event ReportSuperseded(uint256 indexed parentId, uint256 indexed childId);
    event ReportDisputed(uint256 indexed id, address indexed disputer, bytes32 reasonHash);
    event StatusChanged(uint256 indexed id, Status from, Status to, address indexed by);
    event ValidatorAdded(address indexed account);
    event ValidatorRemoved(address indexed account);
    event ReporterAdded(address indexed account);
    event ReporterRemoved(address indexed account);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event DisputeBondChanged(uint256 previous, uint256 current);
    event DisputeResolved(uint256 indexed id, address indexed disputer, bool upheld, uint256 bond);
    event Withdrawal(address indexed account, uint256 amount);

    struct Dispute {
        address disputer;
        uint96 bond;
    }

    // ---------- storage ----------
    address public owner;
    mapping(address => bool) public isValidator;
    mapping(address => bool) public isReporter;

    Report[] private _reports; // index 0 is an unused sentinel
    mapping(bytes32 => uint256) private _idOfHash;

    uint96 public disputeBond;
    mapping(uint256 => Dispute) private _openDispute; // set while a report is Disputed
    mapping(address => uint256) public pendingWithdrawal;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyValidator() {
        if (!isValidator[msg.sender]) revert NotValidator();
        _;
    }

    modifier onlyReporter() {
        if (!isReporter[msg.sender]) revert NotReporter();
        _;
    }

    constructor() {
        owner = msg.sender;
        _reports.push(); // sentinel so real ids start at 1
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ---------- reports ----------

    /// @notice Commit a report hash (authorised reporters only). If `parentHash` is non-zero, the caller must own the
    ///         parent, which becomes Superseded.
    function submitReport(bytes32 reportHash, bytes32 parentHash) external onlyReporter returns (uint256 id) {
        if (reportHash == bytes32(0)) revert ZeroHash();
        if (_idOfHash[reportHash] != 0) revert DuplicateHash(reportHash);

        uint256 parentId;
        if (parentHash != bytes32(0)) {
            parentId = _idOfHash[parentHash];
            if (parentId == 0) revert ParentNotFound(parentHash);
            Report storage parent = _reports[parentId];
            if (parent.reporter != msg.sender) revert NotParentOwner(parentId);
            if (parent.status == Status.Superseded) revert ParentAlreadySuperseded(parentId);
            if (parent.status == Status.Rejected) revert ParentRejected(parentId);
        }

        id = _reports.length;
        _reports.push(
            Report({
                reportHash: reportHash,
                parentHash: parentHash,
                reporter: msg.sender,
                createdAt: uint64(block.timestamp),
                status: Status.Submitted
            })
        );
        _idOfHash[reportHash] = id;
        emit ReportSubmitted(id, reportHash, parentHash, msg.sender);

        if (parentId != 0) {
            Report storage parent = _reports[parentId];
            Status prev = parent.status;
            if (prev == Status.Disputed) _settle(parentId, true); // the reporter revised it: the disputer was right
            parent.status = Status.Superseded;
            emit StatusChanged(parentId, prev, Status.Superseded, msg.sender);
            emit ReportSuperseded(parentId, id);
        }
    }

    /// @notice Anyone may dispute a Submitted or Validated report by posting exactly `disputeBond` wei.
    function disputeReport(uint256 id, bytes32 reasonHash) external payable {
        Report storage r = _get(id);
        if (reasonHash == bytes32(0)) revert ZeroHash();
        if (msg.value != disputeBond) revert WrongBond(msg.value, disputeBond);
        Status prev = r.status;
        if (prev != Status.Submitted && prev != Status.Validated) revert InvalidTransition(prev, Status.Disputed);
        r.status = Status.Disputed;
        // forge-lint: disable-next-line(unsafe-typecast)
        _openDispute[id] = Dispute({disputer: msg.sender, bond: uint96(msg.value)}); // == disputeBond, fits
        emit ReportDisputed(id, msg.sender, reasonHash);
        emit StatusChanged(id, prev, Status.Disputed, msg.sender);
    }

    /// @notice Validators resolve a report to Validated or Rejected. Rejected and Superseded are terminal.
    function setStatus(uint256 id, Status s) external onlyValidator {
        if (s != Status.Validated && s != Status.Rejected) revert InvalidStatus(s);
        Report storage r = _get(id);
        Status prev = r.status;
        if (prev == Status.Rejected || prev == Status.Superseded || prev == s) revert InvalidTransition(prev, s);
        if (prev == Status.Disputed) _settle(id, s == Status.Rejected);
        r.status = s;
        emit StatusChanged(id, prev, s, msg.sender);
    }

    /// @notice Collect bonds returned or forfeited to you.
    function withdraw() external {
        uint256 amount = pendingWithdrawal[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        pendingWithdrawal[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function getDispute(uint256 id) external view returns (Dispute memory) {
        _get(id);
        return _openDispute[id];
    }

    function getReport(uint256 id) external view returns (Report memory) {
        return _get(id);
    }

    function idOfHash(bytes32 reportHash) external view returns (uint256) {
        return _idOfHash[reportHash];
    }

    function reportCount() external view returns (uint256) {
        return _reports.length - 1;
    }

    // ---------- admin ----------

    function addValidator(address account) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (isValidator[account]) revert AlreadyValidator(account);
        isValidator[account] = true;
        emit ValidatorAdded(account);
    }

    function removeValidator(address account) external onlyOwner {
        if (!isValidator[account]) revert NotAValidator(account);
        isValidator[account] = false;
        emit ValidatorRemoved(account);
    }

    function addReporter(address account) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (isReporter[account]) revert AlreadyReporter(account);
        isReporter[account] = true;
        emit ReporterAdded(account);
    }

    /// @notice Revoking a reporter does not touch reports it already submitted.
    function removeReporter(address account) external onlyOwner {
        if (!isReporter[account]) revert NotAReporter(account);
        isReporter[account] = false;
        emit ReporterRemoved(account);
    }

    function setDisputeBond(uint96 bond) external onlyOwner {
        emit DisputeBondChanged(disputeBond, bond);
        disputeBond = bond;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @dev Credit the open dispute's bond: to the disputer if upheld, else to the current owner. Clears the dispute.
    function _settle(uint256 id, bool upheld) private {
        Dispute memory d = _openDispute[id];
        delete _openDispute[id];
        pendingWithdrawal[upheld ? d.disputer : owner] += d.bond;
        emit DisputeResolved(id, d.disputer, upheld, d.bond);
    }

    function _get(uint256 id) private view returns (Report storage) {
        if (id == 0 || id >= _reports.length) revert ReportNotFound(id);
        return _reports[id];
    }
}

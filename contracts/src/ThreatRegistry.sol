// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ThreatRegistry
/// @notice Append-only registry of CyberMatrix threat-report commitments.
/// @dev Only hashes, status, timestamps and the reporter address are stored. Raw report content stays off-chain.
///      No upgradability, no external calls. Report ids start at 1; id 0 means "not registered".
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

    // ---------- events ----------
    event ReportSubmitted(uint256 indexed id, bytes32 indexed reportHash, bytes32 parentHash, address indexed reporter);
    event ReportSuperseded(uint256 indexed parentId, uint256 indexed childId);
    event ReportDisputed(uint256 indexed id, address indexed disputer, bytes32 reasonHash);
    event StatusChanged(uint256 indexed id, Status from, Status to, address indexed by);
    event ValidatorAdded(address indexed account);
    event ValidatorRemoved(address indexed account);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ---------- storage ----------
    address public owner;
    mapping(address => bool) public isValidator;

    Report[] private _reports; // index 0 is an unused sentinel
    mapping(bytes32 => uint256) private _idOfHash;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyValidator() {
        if (!isValidator[msg.sender]) revert NotValidator();
        _;
    }

    constructor() {
        owner = msg.sender;
        _reports.push(); // sentinel so real ids start at 1
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ---------- reports ----------

    /// @notice Commit a report hash. If `parentHash` is non-zero, the caller must own the parent, which becomes Superseded.
    function submitReport(bytes32 reportHash, bytes32 parentHash) external returns (uint256 id) {
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
            parent.status = Status.Superseded;
            emit StatusChanged(parentId, prev, Status.Superseded, msg.sender);
            emit ReportSuperseded(parentId, id);
        }
    }

    /// @notice Anyone may dispute a Submitted or Validated report.
    function disputeReport(uint256 id, bytes32 reasonHash) external {
        Report storage r = _get(id);
        if (reasonHash == bytes32(0)) revert ZeroHash();
        Status prev = r.status;
        if (prev != Status.Submitted && prev != Status.Validated) revert InvalidTransition(prev, Status.Disputed);
        r.status = Status.Disputed;
        emit ReportDisputed(id, msg.sender, reasonHash);
        emit StatusChanged(id, prev, Status.Disputed, msg.sender);
    }

    /// @notice Validators resolve a report to Validated or Rejected. Rejected and Superseded are terminal.
    function setStatus(uint256 id, Status s) external onlyValidator {
        if (s != Status.Validated && s != Status.Rejected) revert InvalidStatus(s);
        Report storage r = _get(id);
        Status prev = r.status;
        if (prev == Status.Rejected || prev == Status.Superseded || prev == s) revert InvalidTransition(prev, s);
        r.status = s;
        emit StatusChanged(id, prev, s, msg.sender);
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

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function _get(uint256 id) private view returns (Report storage) {
        if (id == 0 || id >= _reports.length) revert ReportNotFound(id);
        return _reports[id];
    }
}

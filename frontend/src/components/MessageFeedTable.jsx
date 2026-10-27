import React, { useState, useMemo } from "react";
import {
  Search,
  Filter,
  RefreshCw,
  ChevronRight,
  ChevronLeft,
  ArrowUpDown,
  Mail,
  Smartphone
} from "lucide-react";
import { SourceBadge, CategoryBadge, RiskScoreBadge } from "./StatusBadge";
import { EmptyState } from "./EmptyState";
import { LoadingSkeleton } from "./LoadingSkeleton";

export function MessageFeedTable({
  messages = [],
  loading = false,
  sourceFilter = "ALL",
  setSourceFilter,
  categoryFilter = "ALL",
  setCategoryFilter,
  searchQuery = "",
  setSearchQuery,
  onRefresh,
  onSelectMessage,
  selectedMessageId,
  sortBy = "time", // 'time' | 'risk'
  setSortBy,
  itemsPerPage = 10
}) {
  const [currentPage, setCurrentPage] = useState(1);

  // Reset to page 1 when filters or search change
  React.useEffect(() => {
    setCurrentPage(1);
  }, [sourceFilter, categoryFilter, searchQuery, sortBy]);

  // Paginated slice
  const totalCount = messages.length;
  const totalPages = Math.max(1, Math.ceil(totalCount / itemsPerPage));
  const validPage = Math.min(currentPage, totalPages);
  const startIndex = (validPage - 1) * itemsPerPage;
  const paginatedMessages = useMemo(() => {
    return messages.slice(startIndex, startIndex + itemsPerPage);
  }, [messages, startIndex, itemsPerPage]);

  return (
    <div className="table-container-card">
      {/* Table Toolbar */}
      <div className="table-toolbar">
        <div className="toolbar-left">
          {/* Source Tabs */}
          {setSourceFilter && (
            <div className="filter-pill-group" role="tablist" aria-label="Filter by source channel">
              <button
                type="button"
                role="tab"
                aria-selected={sourceFilter === "ALL"}
                className={`filter-pill ${sourceFilter === "ALL" ? "active" : ""}`}
                onClick={() => setSourceFilter("ALL")}
              >
                All Sources
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={sourceFilter === "GMAIL"}
                className={`filter-pill ${sourceFilter === "GMAIL" ? "active" : ""}`}
                onClick={() => setSourceFilter("GMAIL")}
              >
                <Mail size={12} />
                <span>Gmail</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={sourceFilter === "SMS"}
                className={`filter-pill ${sourceFilter === "SMS" ? "active" : ""}`}
                onClick={() => setSourceFilter("SMS")}
              >
                <Smartphone size={12} />
                <span>SMS</span>
              </button>
            </div>
          )}

          {/* Category Dropdown */}
          {setCategoryFilter && (
            <div className="select-wrap">
              <select
                className="custom-select"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                aria-label="Filter by classification"
              >
                <option value="ALL">All Categories</option>
                <option value="LEGITIMATE">Legitimate</option>
                <option value="NEEDS REVIEW">Needs Review</option>
                <option value="SPAM">Spam</option>
                <option value="PHISHING">Phishing</option>
              </select>
            </div>
          )}

          {/* Sort Control */}
          {setSortBy && (
            <div className="select-wrap">
              <select
                className="custom-select"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                aria-label="Sort messages by"
              >
                <option value="time">Sort: Newest First</option>
                <option value="risk">Sort: Highest Threat</option>
              </select>
            </div>
          )}
        </div>

        <div className="toolbar-right">
          {/* Search Input */}
          {setSearchQuery && (
            <div className="search-input-wrap">
              <Search size={14} className="search-icon" aria-hidden="true" />
              <input
                type="text"
                placeholder="Search sender, subject, text..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="table-search-input"
                aria-label="Search within messages"
              />
            </div>
          )}

          {/* Refresh Button */}
          {onRefresh && (
            <button
              type="button"
              className="btn btn-ghost btn-sm btn-icon-only"
              onClick={onRefresh}
              disabled={loading}
              title="Refresh security records"
              aria-label="Refresh security records"
            >
              <RefreshCw size={14} className={loading ? "spin" : ""} />
            </button>
          )}
        </div>
      </div>

      {/* Messages Table */}
      <div className="table-responsive">
        <table className="dense-table" aria-label="Security classifications table">
          <thead>
            <tr>
              <th scope="col" style={{ width: "95px" }}>Source</th>
              <th scope="col" style={{ width: "160px" }}>Sender</th>
              <th scope="col">Subject / Message Preview</th>
              <th scope="col" style={{ width: "135px" }}>Classification</th>
              <th scope="col" style={{ width: "90px" }}>Threat</th>
              <th scope="col" style={{ width: "125px" }}>Timestamp</th>
              <th scope="col" style={{ width: "40px" }} aria-label="Details link"></th>
            </tr>
          </thead>
          <tbody>
            {loading && messages.length === 0 ? (
              <LoadingSkeleton type="table-row" rows={6} />
            ) : messages.length === 0 ? (
              <tr>
                <td colSpan={7} className="table-empty-cell">
                  <EmptyState
                    title="No Security Events Found"
                    description={
                      searchQuery || categoryFilter !== "ALL" || sourceFilter !== "ALL"
                        ? "No messages match your selected filters. Try broadening your search or filter options."
                        : "No analyzed messages found. Connect Gmail or an Android device to stream and analyze incoming communications."
                    }
                  />
                </td>
              </tr>
            ) : (
              paginatedMessages.map((item) => {
                const isSelected = selectedMessageId === item.id;
                const senderDisplay = item.from || item.sender || "Unknown";
                const preview = item.subject || item.snippet || item.body || "(No message body)";
                const timeDisplay = item.timestamp
                  ? new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
                  : "Recently";

                return (
                  <tr
                    key={item.id}
                    tabIndex={0}
                    className={`dense-row ${isSelected ? "row-selected" : ""} ${item.category === "PHISHING" ? "row-threat" : ""}`}
                    onClick={() => onSelectMessage && onSelectMessage(item)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        if (onSelectMessage) onSelectMessage(item);
                      }
                    }}
                    role="button"
                    aria-label={`View classification details for message from ${senderDisplay}`}
                  >
                    <td>
                      <SourceBadge source={item.source} />
                    </td>
                    <td className="sender-cell">
                      <span className="sender-text" title={senderDisplay}>
                        {senderDisplay}
                      </span>
                    </td>
                    <td className="preview-cell">
                      <div className="preview-line">
                        <span className="preview-text" title={preview}>
                          {preview}
                        </span>
                      </div>
                    </td>
                    <td>
                      <CategoryBadge category={item.category} />
                    </td>
                    <td>
                      <RiskScoreBadge score={item.score} />
                    </td>
                    <td className="time-cell">
                      <span className="time-text text-muted" title={item.timestamp ? new Date(item.timestamp).toLocaleString() : ""}>
                        {timeDisplay}
                      </span>
                    </td>
                    <td className="action-cell">
                      <ChevronRight size={14} className="chevron-icon text-muted" />
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Table Pagination Footer */}
      {totalCount > 0 && (
        <div className="table-pagination-footer">
          <div className="pagination-info">
            Showing <span className="font-semibold">{Math.min(totalCount, startIndex + 1)}</span> to{" "}
            <span className="font-semibold">{Math.min(totalCount, startIndex + itemsPerPage)}</span> of{" "}
            <span className="font-semibold">{totalCount}</span> messages
          </div>

          {totalPages > 1 && (
            <div className="pagination-controls" aria-label="Pagination">
              <button
                type="button"
                className="btn-pagination"
                disabled={validPage <= 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                aria-label="Previous page"
              >
                <ChevronLeft size={14} />
              </button>

              {Array.from({ length: totalPages }).map((_, i) => {
                const pageNum = i + 1;
                if (
                  totalPages <= 7 ||
                  pageNum === 1 ||
                  pageNum === totalPages ||
                  Math.abs(pageNum - validPage) <= 1
                ) {
                  return (
                    <button
                      key={pageNum}
                      type="button"
                      className={`btn-pagination ${pageNum === validPage ? "active" : ""}`}
                      onClick={() => setCurrentPage(pageNum)}
                      aria-current={pageNum === validPage ? "page" : undefined}
                    >
                      {pageNum}
                    </button>
                  );
                } else if (
                  (pageNum === 2 && validPage > 4) ||
                  (pageNum === totalPages - 1 && validPage < totalPages - 3)
                ) {
                  return (
                    <span key={pageNum} className="pagination-ellipsis">
                      ...
                    </span>
                  );
                }
                return null;
              })}

              <button
                type="button"
                className="btn-pagination"
                disabled={validPage >= totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                aria-label="Next page"
              >
                <ChevronRight size={14} />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

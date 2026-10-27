import React, { useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { MessageFeedTable } from "../components/MessageFeedTable";

export function FeedPage({
  allMessages = [],
  loading = false,
  onRefresh,
  sourceFilter,
  setSourceFilter,
  categoryFilter,
  setCategoryFilter,
  searchQuery,
  setSearchQuery,
  onSelectMessage,
  selectedMessageId,
  onNavigateOverview
}) {
  const [sortBy, setSortBy] = useState("time");

  // Sorted messages
  const sortedMessages = [...allMessages].sort((a, b) => {
    if (sortBy === "risk") {
      return (b.score || 0) - (a.score || 0);
    }
    const tA = a.timestamp || 0;
    const tB = b.timestamp || 0;
    return tB - tA;
  });

  const totalCount = sortedMessages.length;
  const phishingCount = sortedMessages.filter((m) => m.category === "PHISHING").length;
  const reviewCount = sortedMessages.filter((m) => m.category === "NEEDS REVIEW" || m.category === "SUSPICIOUS").length;
  const spamCount = sortedMessages.filter((m) => m.category === "SPAM").length;

  return (
    <div className="page-container feed-page">
      {/* Reusable Enterprise Page Header */}
      <PageHeader
        breadcrumbs={["Sentinel AI", "Mail & SMS Feed"]}
        onBreadcrumbClick={() => onNavigateOverview && onNavigateOverview()}
        title="Mail & SMS Threat Intelligence Feed"
        description="Full-spectrum chronological stream of incoming email communications and synchronized Android SMS messages."
        onRefresh={onRefresh}
        loading={loading}
        actions={
          <div className="feed-header-stats-row">
            <div className="stat-pill">
              <span className="stat-pill-label">Total Messages</span>
              <span className="stat-pill-val">{totalCount}</span>
            </div>
            {phishingCount > 0 && (
              <div className="stat-pill stat-pill-danger">
                <span className="stat-pill-label">Phishing</span>
                <span className="stat-pill-val">{phishingCount}</span>
              </div>
            )}
            {reviewCount > 0 && (
              <div className="stat-pill stat-pill-amber">
                <span className="stat-pill-label">Needs Review</span>
                <span className="stat-pill-val">{reviewCount}</span>
              </div>
            )}
            {spamCount > 0 && (
              <div className="stat-pill stat-pill-warning">
                <span className="stat-pill-label">Spam</span>
                <span className="stat-pill-val">{spamCount}</span>
              </div>
            )}
          </div>
        }
      />

      {/* Full-Width Security Feed Table Card */}
      <div className="feed-table-wrapper">
        <MessageFeedTable
          messages={sortedMessages}
          loading={loading}
          sourceFilter={sourceFilter}
          setSourceFilter={setSourceFilter}
          categoryFilter={categoryFilter}
          setCategoryFilter={setCategoryFilter}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          onRefresh={onRefresh}
          onSelectMessage={onSelectMessage}
          selectedMessageId={selectedMessageId}
          sortBy={sortBy}
          setSortBy={setSortBy}
          itemsPerPage={12}
        />
      </div>
    </div>
  );
}

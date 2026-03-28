# QUT Canvas Assignment Discovery Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Navigate QUT Canvas, enumerate all enrolled courses, and compile a complete list of every assignment with its name, due date, weight, and description.

**Architecture:** Use Claude's built-in Chrome browser automation to log in to Canvas, enumerate courses from the dashboard, then iterate through each course's Assignments page to extract structured data. All findings compiled into a single markdown table at the end.

**Tech Stack:** Chrome browser automation (mcp__claude-in-chrome__*), Canvas LMS web UI

---

## Chunk 1: Login & Course Discovery

### Task 1: Open Canvas and check login state

**Browser target:** `https://canvas.qut.edu.au/courses/`

- [ ] **Step 1: Get current tab context**

  Call `tabs_context_mcp` to see what's open in the browser.

- [ ] **Step 2: Create a new tab and navigate to Canvas**

  Navigate to: `https://canvas.qut.edu.au/courses/`

- [ ] **Step 3: Read the page to determine login state**

  Call `get_page_text` or `read_page`.
  - If redirected to SSO/login → proceed to Task 2.
  - If the courses list is visible → skip to Task 3.

- [ ] **Step 4: Capture a screenshot for reference**

  Call `computer` (screenshot action) to confirm what's visible.

---

### Task 2: Authenticate via QUT SSO (if not already logged in)

- [ ] **Step 1: Identify the login form**

  Call `find` to locate the username/email field. QUT uses Microsoft SSO — look for `input[type=email]` or similar.

- [ ] **Step 2: Pause and prompt user for credentials**

  Do NOT proceed automatically with credentials. Instead, tell the user:
  > "Canvas is asking for login. Please log in manually in the browser window, then tell me when you're done."

  Wait for user confirmation before continuing.

- [ ] **Step 3: Verify login succeeded**

  After user confirms, call `get_page_text` — confirm the courses page or dashboard is now visible.

---

### Task 3: Enumerate all enrolled courses

- [ ] **Step 1: Navigate to the All Courses page**

  Navigate to: `https://canvas.qut.edu.au/courses/`
  This page lists all current and past enrolments.

- [ ] **Step 2: Extract course list**

  Call `get_page_text` and extract:
  - Course name
  - Course URL (e.g. `/courses/12345`)
  - Term/semester label if shown

  Record the full list. Note: only include **active/current** courses unless the user wants all.

- [ ] **Step 3: Filter to current semester only**

  Identify which courses are current (Canvas labels them "Current Enrollments"). Discard past courses unless instructed otherwise.

  Ask user: "I found [N] current courses and [M] past courses. Should I check assignments for current courses only, or all of them?"

---

## Chunk 2: Assignment Extraction Per Course

*Repeat Tasks 4–5 for each course identified in Task 3.*

### Task 4: Navigate to a course's Assignments page

- [ ] **Step 1: Navigate to the course Assignments tab**

  URL pattern: `https://canvas.qut.edu.au/courses/<COURSE_ID>/assignments`

- [ ] **Step 2: Read the assignments page**

  Call `get_page_text`. Canvas groups assignments by type (e.g., "Assignments", "Quizzes", "Discussions").

- [ ] **Step 3: Extract all assignment entries**

  For each assignment, capture:
  - Assignment name
  - Due date (including time if shown)
  - Points/weight (if shown)
  - Submission type (online, paper, etc.)

- [ ] **Step 4: Click into each assignment for full details**

  For any assignment without a visible due date or description on the list view, click through to the individual assignment page and extract:
  - Full description / instructions summary
  - Due date
  - Available from / until dates
  - Submission requirements

---

### Task 5: Check the Syllabus page for additional context

- [ ] **Step 1: Navigate to the course Syllabus**

  URL pattern: `https://canvas.qut.edu.au/courses/<COURSE_ID>/assignments/syllabus`

- [ ] **Step 2: Extract any assignment schedule**

  The syllabus view shows all graded items in chronological order with due dates — often more complete than the Assignments tab.

- [ ] **Step 3: Cross-reference with Task 4 data**

  Check for any items on the syllabus not captured in Task 4 (e.g., participation grades, weekly quizzes).

---

## Chunk 3: Compile & Present Results

### Task 6: Build the master assignment table

- [ ] **Step 1: Compile all data collected**

  Organise by due date (ascending). Group by course.

- [ ] **Step 2: Output the full table in this format:**

```markdown
## [Course Name]

| Assignment | Due Date | Weight | Type | Notes |
|---|---|---|---|---|
| Assignment 1 | Wed 19 Mar 2026, 11:59 PM | 30% | Online submission | ... |
| Quiz 1 | Fri 21 Mar 2026, 9:00 AM | 10% | Canvas quiz | ... |
```

- [ ] **Step 3: Show a combined chronological view**

  After the per-course tables, show a single merged table sorted by due date across all courses — this is the most useful daily reference.

- [ ] **Step 4: Flag anything due within 7 days**

  Highlight (bold) any assignment due on or before **2026-03-19**.

---

## Notes for Execution

- If Canvas requires Duo MFA or Microsoft Authenticator during login, pause and wait for user to approve.
- Canvas sometimes lazy-loads assignment lists. If `get_page_text` returns an incomplete list, use `javascript_tool` to scroll or trigger a full render before reading.
- Do NOT click any "Submit" buttons or modify any submissions.
- If a course has no assignments yet, note it as "No assignments posted."

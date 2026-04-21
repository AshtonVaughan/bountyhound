// Browser script to fetch detailed program information
// This runs in the browser context while logged into HackerOne

const PROGRAM_DETAILS_QUERY = `
query ProgramDetails($handle: String!) {
  team(handle: $handle) {
    id
    handle
    name

    in_scope_assets: structured_scopes(
      first: 100
      archived: false
      eligible_for_submission: true
    ) {
      edges {
        node {
          id
          asset_type
          asset_identifier
          instruction
          max_severity
          eligible_for_bounty
          eligible_for_submission
        }
      }
    }

    out_of_scope_assets: structured_scopes(
      first: 100
      archived: false
      eligible_for_submission: false
    ) {
      edges {
        node {
          id
          asset_type
          asset_identifier
          instruction
        }
      }
    }

    bounty_table {
      id
      critical_minimum_bounty
      critical_maximum_bounty
      high_minimum_bounty
      high_maximum_bounty
      medium_minimum_bounty
      medium_maximum_bounty
      low_minimum_bounty
      low_maximum_bounty
    }

    disclosed_reports: hacktivity_items(
      first: 20
      type: HACKTIVITY_TYPE_HACKTIVITY
    ) {
      edges {
        node {
          ... on Disclosed {
            id
            report {
              id
              title
              substate
              severity_rating: severity {
                rating
              }
              disclosed_at
              vulnerability_information
            }
          }
        }
      }
    }
  }
}
`;

async function fetchProgramDetails(handles) {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.content : null;

    if (!csrfToken) {
        return { error: "No CSRF token found" };
    }

    const results = [];
    let processed = 0;

    for (const handle of handles) {
        try {
            const response = await fetch('https://hackerone.com/graphql', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include',
                body: JSON.stringify({
                    query: PROGRAM_DETAILS_QUERY,
                    variables: { handle }
                })
            });

            const data = await response.json();
            results.push({
                handle,
                data: data.data,
                errors: data.errors
            });

            processed++;
            if (processed % 10 === 0) {
                console.log(`Processed ${processed}/${handles.length}...`);
            }

            // Rate limiting - 1 second between requests
            await new Promise(resolve => setTimeout(resolve, 1000));

        } catch (error) {
            results.push({
                handle,
                error: error.message
            });
        }
    }

    return {
        total: handles.length,
        processed,
        results
    };
}

// Execute if handles are provided
if (typeof PROGRAM_HANDLES !== 'undefined') {
    fetchProgramDetails(PROGRAM_HANDLES);
} else {
    // Return function for manual execution
    fetchProgramDetails;
}

# DACLhound 0.1.42

## Viewer

- Improve the automatic overview layout for disconnected graph components and dense relationships.
- Prevent text selection while dragging the graph canvas and restore the main overview when returning Home.
- Keep graph labels available in the default view and improve navigation after clearing a selection.

## Collector and analysis

- Create SQL service relationships only when an MSSQLSvc SPN host resolves uniquely to a collected computer; retain the SPN on its account otherwise.
- Exclude unresolved synthetic SQL service targets from path analysis.
- Recognize the additional built-in RID 517 trustee during analysis.

# Browser Artifact Extractor - Memory

## Architecture
- Single-file tkinter application
- Browser detection via path enumeration
- Simulated data extraction for demonstration

## Design Decisions
- **Multi-browser Support**: Chrome, Firefox, Edge with different database formats
- **Search**: Real-time filtering on history URLs and titles
- **Danger Classification**: Downloads flagged as High/Medium/Low/None
- **Cookie Security**: Track Secure and HttpOnly flags

## Data Model

### History Entry
```python
{
    "id": int,
    "url": str,
    "title": str,
    "visit_count": int,
    "last_visit": str,  # "YYYY-MM-DD HH:MM:SS"
    "typed_count": int,
    "browser": str
}
```

### Cookie Entry
```python
{
    "host": str,
    "name": str,
    "value": str,
    "path": str,
    "expires": str,
    "secure": str,    # "Yes" or "No"
    "http_only": str, # "Yes" or "No"
    "browser": str
}
```

### Download Entry
```python
{
    "id": int,
    "url": str,
    "filename": str,
    "start_time": str,
    "end_time": str,
    "size": str,
    "state": str,     # "Completed", "In Progress", "Interrupted"
    "danger": str,    # "None", "Low", "Medium", "High"
    "browser": str
}
```

## Browser Database Locations
- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History`

## Statistical Analysis
- Top domains by visit count
- Cookie name frequency
- Download danger classification
- Browser usage comparison

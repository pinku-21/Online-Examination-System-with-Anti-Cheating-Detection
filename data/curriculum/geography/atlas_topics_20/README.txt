INDIA & WORLD MAP EXAM CSV DATASETS
====================================

This package contains one CSV per each of the 20 map topics, plus a master CSV.
Each row is a feature that can be used to create an answer map or a student
locate-and-label question.

Columns:
- map_topic: source topic filename
- feature: feature name
- location_or_region: state, country, or broad region
- label: category/type
- latitude_approx / longitude_approx: approximate point coordinates where relevant
- teacher_note: cautions and context

Important:
1. Coordinates are approximate teaching references, not survey-grade coordinates.
2. Broad thematic areas (soil, climate, rainfall, agriculture, minerals, world climate)
   intentionally have blank coordinates because they are regions, not single points.
3. Lines/ranges/rivers cannot be accurately represented by one coordinate; use an
   authoritative map for their actual shapes.
4. This is a starter educational dataset, not an official CBSE/ICSE syllabus list.
   Check the current syllabus for each class and academic year.
5. Political boundaries change. Use current official maps for exam printing.
6. Answer maps should be built from a reliable base map; do not plot these approximate
   points as exact boundaries or routes.

Suggested authoritative references:
- Survey of India: https://surveyofindia.gov.in/
- CBSE Academic: https://cbseacademic.nic.in/
- CISCE: https://cisce.org/
- NCERT: https://ncert.nic.in/textbook.php
- Natural Earth world data: https://www.naturalearthdata.com/downloads/
- India-WRIS: https://indiawris.gov.in/

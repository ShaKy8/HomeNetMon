#!/usr/bin/env python3
"""
Database Pagination Service
Provides efficient pagination for large result sets with performance optimizations.
"""

import logging
import math
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy import func, text
from sqlalchemy.orm import Query
from flask import request

logger = logging.getLogger(__name__)

class DatabasePaginator:
    """High-performance database pagination with optimized queries."""
    
    def __init__(self, db_session=None):
        self.db_session = db_session
        self.default_page_size = 25
        self.max_page_size = 1000
        
    def paginate_query(self, query: Query, page: int = 1, per_page: Optional[int] = None,
                      error_out: bool = True, max_per_page: Optional[int] = None) -> Dict[str, Any]:
        """
        Paginate a SQLAlchemy query with performance optimizations.
        
        Args:
            query: SQLAlchemy Query object
            page: Page number (1-based)
            per_page: Items per page
            error_out: Raise error on invalid page
            max_per_page: Maximum items per page
            
        Returns:
            Dictionary with pagination data and items
        """
        if per_page is None:
            per_page = self.default_page_size
        
        if max_per_page is None:
            max_per_page = self.max_page_size
            
        # Validate and constrain per_page
        per_page = min(per_page, max_per_page)
        per_page = max(1, per_page)
        
        # Validate page number
        page = max(1, page)
        
        # Get total count efficiently
        total = self._get_total_count(query)
        
        if total == 0:
            return {
                'items': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'pages': 0,
                'has_prev': False,
                'prev_num': None,
                'has_next': False,
                'next_num': None,
                'iter_pages': []
            }
        
        # Calculate pagination values
        pages = math.ceil(total / per_page)
        
        # Handle page out of bounds
        if page > pages:
            if error_out:
                raise ValueError(f"Page {page} out of range (1-{pages})")
            page = pages
        
        # Calculate offset and get items
        offset = (page - 1) * per_page
        items = query.offset(offset).limit(per_page).all()
        
        # Build pagination metadata
        has_prev = page > 1
        has_next = page < pages
        prev_num = page - 1 if has_prev else None
        next_num = page + 1 if has_next else None
        
        return {
            'items': items,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': pages,
            'has_prev': has_prev,
            'prev_num': prev_num,
            'has_next': has_next,
            'next_num': next_num,
            'iter_pages': self._iter_pages(page, pages)
        }
    
    def _get_total_count(self, query: Query) -> int:
        """
        Get total count efficiently using optimized counting.
        
        For large tables, this uses approximate counting where appropriate.
        """
        try:
            # Try to get an exact count first
            count_query = query.statement.with_only_columns(func.count()).order_by(None)
            return query.session.execute(count_query).scalar()
            
        except Exception as e:
            logger.warning(f"Count query failed, using fallback: {e}")
            # Fallback to basic count
            return query.count()
    
    def _iter_pages(self, page: int, pages: int, left_edge: int = 2, 
                   left_current: int = 2, right_current: int = 3, 
                   right_edge: int = 2) -> List[Optional[int]]:
        """
        Generate page numbers for pagination navigation.
        
        Returns a list with page numbers and None for gaps.
        """
        last = pages
        
        for num in range(1, last + 1):
            if (num <= left_edge or
                (page - left_current - 1 < num < page + right_current) or
                num > last - right_edge):
                yield num

    def paginate_raw_sql(self, sql: str, params: Dict[str, Any], 
                        page: int = 1, per_page: int = 25) -> Dict[str, Any]:
        """
        Paginate raw SQL queries efficiently.
        
        Args:
            sql: Raw SQL query (without LIMIT/OFFSET)
            params: Query parameters
            page: Page number
            per_page: Items per page
            
        Returns:
            Pagination result dictionary
        """
        if not self.db_session:
            raise ValueError("Database session required for raw SQL pagination")
        
        # Get total count
        count_sql = f"SELECT COUNT(*) FROM ({sql}) AS count_query"
        total = self.db_session.execute(text(count_sql), params).scalar()
        
        if total == 0:
            return {
                'items': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'pages': 0
            }
        
        # Calculate pagination
        pages = math.ceil(total / per_page)
        page = min(page, pages)
        offset = (page - 1) * per_page
        
        # Execute paginated query
        paginated_sql = f"{sql} LIMIT {per_page} OFFSET {offset}"
        result = self.db_session.execute(text(paginated_sql), params)
        items = [dict(row) for row in result]
        
        return {
            'items': items,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': pages,
            'has_prev': page > 1,
            'has_next': page < pages
        }

    def get_request_pagination(self) -> Tuple[int, int]:
        """
        Extract pagination parameters from Flask request.
        
        Returns:
            Tuple of (page, per_page)
        """
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', self.default_page_size, type=int)
        
        # Validate and constrain
        page = max(1, page)
        per_page = min(per_page, self.max_page_size)
        per_page = max(1, per_page)
        
        return page, per_page


class OptimizedPaginator:
    """
    Cursor-based pagination for very large datasets.
    More efficient than offset-based pagination for deep pages.
    """
    
    def __init__(self, db_session=None):
        self.db_session = db_session
    
    def cursor_paginate(self, query: Query, cursor_column, cursor_value=None, 
                       limit: int = 25, direction: str = 'next') -> Dict[str, Any]:
        """
        Cursor-based pagination using a sortable column.
        
        Args:
            query: Base SQLAlchemy query
            cursor_column: Column to use for cursor (must be sortable and unique)
            cursor_value: Starting cursor value (None for first page)
            limit: Number of items to return
            direction: 'next' or 'prev'
            
        Returns:
            Dictionary with items and cursor information
        """
        # Build the query with cursor filtering
        if cursor_value is not None:
            if direction == 'next':
                query = query.filter(cursor_column > cursor_value)
            else:
                query = query.filter(cursor_column < cursor_value)
        
        # Order and limit
        if direction == 'next':
            query = query.order_by(cursor_column.asc())
        else:
            query = query.order_by(cursor_column.desc())
        
        # Get one extra item to check if there are more pages
        items = query.limit(limit + 1).all()
        
        has_more = len(items) > limit
        if has_more:
            items = items[:limit]
        
        # Get cursor values
        start_cursor = items[0] if items else None
        end_cursor = items[-1] if items else None
        
        if direction == 'prev':
            items = list(reversed(items))
        
        return {
            'items': items,
            'has_next': has_more if direction == 'next' else bool(cursor_value),
            'has_prev': has_more if direction == 'prev' else bool(cursor_value),
            'start_cursor': getattr(start_cursor, cursor_column.name) if start_cursor else None,
            'end_cursor': getattr(end_cursor, cursor_column.name) if end_cursor else None,
            'count': len(items)
        }


def create_pagination_response(pagination_result: Dict[str, Any], 
                             endpoint: str = None) -> Dict[str, Any]:
    """
    Create a standardized API response for paginated data.
    
    Args:
        pagination_result: Result from paginate_query
        endpoint: Flask endpoint name for generating URLs
        
    Returns:
        Standardized pagination response
    """
    from flask import url_for, request
    
    response = {
        'data': pagination_result['items'],
        'pagination': {
            'page': pagination_result['page'],
            'per_page': pagination_result['per_page'],
            'total': pagination_result['total'],
            'pages': pagination_result['pages'],
            'has_prev': pagination_result['has_prev'],
            'has_next': pagination_result['has_next']
        }
    }
    
    # Add navigation URLs if endpoint is provided
    if endpoint:
        base_args = dict(request.args)
        
        if pagination_result['has_prev']:
            base_args['page'] = pagination_result['prev_num']
            response['pagination']['prev_url'] = url_for(endpoint, **base_args)
        
        if pagination_result['has_next']:
            base_args['page'] = pagination_result['next_num']
            response['pagination']['next_url'] = url_for(endpoint, **base_args)
    
    return response


# Global paginator instance
paginator = DatabasePaginator()
cursor_paginator = OptimizedPaginator()
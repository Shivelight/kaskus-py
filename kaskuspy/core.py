# -*- coding: utf-8 -*-
import requests

from .hammer import prepare, make_query
from .models import *

API_BASE = "https://www.kaskus.co.id/api/oauth"
HEADERS = {
    "User-Agent": "Kaskus Android App 3.74.3",
    "Return-type": "text/json",
}


class Kaskus(object):
    """A Kaskus private API wrapper"""

    def __init__(self):
        self.key = "52f7b01bce2f078a32d6b607e9af62"
        self.secret = "38141e11206bbe0cb6b751280634b0"

    def _get(self, path):
        uri = f"{API_BASE}{path}"
        headers = prepare(uri, "GET", self.key, self.secret)
        headers.update(HEADERS)
        result = requests.get(uri, headers=headers)
        if result.status_code != 200:
            raise ErrorResponse(**result.json())
        return result.json()

    # Content

    def getDbUpdate(self):
        r = self._get("/v1/dbupdate")
        return DbUpdateResponse(r)

    # Forum

    def getForumStream(self, category='6', query=None):
        if query is None:
            query = make_query(sort="popular", order="desc", cursor="0",
                               limit=20)
        r = self._get(f"/v1/forum/streams?category={category}&{query}")
        return ForumStreamResponse(r)

    def getThreadList(self, forumId, tags='', query=None):
        if query is None:
            query = make_query(page=1, limit=20)
        r = self._get(f"/v1/forum/{forumId}/threads?include=preview&{query}"
                      f"&tags={tags}")
        return MultipleThreadListResponse(r)

    # ForumList

    def getCategories(self):
        r = self._get("/forumlist")
        return [ForumListResponse(x) for x in r]

    def getFjbCategories(self):
        r = self._get("/v1/categories")
        return [ForumListResponse(x) for x in r]

    # ForumThread

    def getThread(self, threadId, field=None, query=None):
        if field is None:
            field = ("thread,thread_id,total_post,current_page,per_page,open,"
                     "total_page,posts,profilepicture,post_username,"
                     "post_userid,title,decoded,dateline,text,profilepicture,"
                     "usertitle,post_id,reputation_box,pagetext,"
                     "pagetext_noquote,enable_reputation")
        if query is None:
            query = make_query(page=1, limit=20, expand_spoiler="true",
                               image="on")
        r = self._get(f"/v1/forum_thread/{threadId}?field={field}"
                      f"&include=similar&{query}")
        return MultipleThreadResponse(r)

    def getTopVideos(self):
        r = self._get("/v1/top_videos")
        return TopVideoResponse(r)

    # HotThread

    def getHotThreads(self, query=None):
        if query is None:
            query = make_query(clean="forum_name,title")
        r = self._get(f"/v1/hot_threads?{query}")
        return MultipleHotThreadResponse(r)

    # Search

    def searchForum(self, q='*', query=None):
        if query is None:
            query = make_query(cursor="0", sort="lastpost", order="desc",
                               limit=20)
        r = self._get(f"/search/forum?q={q}&{query}")
        return SearchThreadResponse(r)

    # SpecialEvent

    def getSpecialEvents(self, query=None):
        if query is None:
            query = make_query(resize_ratio="r")
        r = self._get(f"/v1/kaskus/special_events?{query}")
        return MultipleSpecialEventResponse(r)

    # User

    def getForumCategoryPermission(self):
        r = self._get("/v1/user/forum_permissions")
        return CategoryPermission(r)

    # Versions

    def checkVersion(self):
        r = self._get("/v1/versions")
        return VersionResponse(r)
